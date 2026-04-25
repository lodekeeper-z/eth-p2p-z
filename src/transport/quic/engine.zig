const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = Io.net;

const ssl = @import("ssl");
const tls = @import("../../security/tls.zig");
const identity = @import("../../identity.zig");
const PeerId = @import("peer_id").PeerId;
const keys = @import("peer_id").keys;

const builtin = @import("builtin");

const log = std.log.scoped(.quic_engine);

const lsquic = @cImport({
    @cInclude("lsquic.h");
    @cInclude("lsquic_types.h");
});

/// Global SSL_CTX ex_data index for storing CertVerifyCtx pointer.
/// Initialized once via SSL_CTX_get_ex_new_index on first engine creation.
var g_ssl_ctx_ex_idx: c_int = -1;

// ── Event types communicated via Io.Queue ──────────────────────────────

/// Event pushed when a connection completes handshake.
pub const ConnEvent = struct {
    conn: *QuicConnection,
};

/// Event pushed when a stream becomes available on a connection.
pub const StreamEvent = struct {
    stream: *QuicStream,
};

/// Event pushed when data is available on a stream.
pub const ReadEvent = struct {
    data: []const u8,
    owned_buf: []u8, // allocated buffer, caller must free
};

pub const WriteEvent = enum(u8) {
    ready,
};

fn tryQueueOneUncancelable(comptime Elem: type, queue: *Io.Queue(Elem), io: Io, item: Elem) Io.QueueClosedError!bool {
    // `min = 0` is std.Io's non-blocking queue mode: enqueue one item if there is
    // room now, otherwise return 0 without suspending inside callback-driven code.
    return (try queue.putUncancelable(io, &.{item}, 0)) == 1;
}

const unsent_retry_interval_ms: i64 = 10;
/// Large req/resp bodies can burst many QUIC read callbacks before the
/// application stream reader is rescheduled.
const stream_read_queue_capacity: usize = 8192;

pub const QuicDebugStats = struct {
    timer_immediate_count: u64 = 0,
    timer_timeout_count: u64 = 0,
    timer_indefinite_count: u64 = 0,
    current_consecutive_immediate_ticks: u64 = 0,
    max_consecutive_immediate_ticks: u64 = 0,
    advisory_tick_count: u64 = 0,
    latest_advisory_diff_us: ?i64 = null,
    min_advisory_diff_us: ?i64 = null,
    max_advisory_diff_us: ?i64 = null,
    process_engine_count: u64 = 0,
    process_engine_reentrant_skip_count: u64 = 0,
    process_engine_total_ns: u64 = 0,
    process_engine_max_ns: u64 = 0,
    on_read_count: u64 = 0,
    on_read_bytes: u64 = 0,
    on_read_would_block_count: u64 = 0,
    on_read_zero_before_data_count: u64 = 0,
    on_read_eof_count: u64 = 0,
    read_queue_full_count: u64 = 0,
    read_queue_closed_count: u64 = 0,
    accept_queue_full_count: u64 = 0,
    accept_queue_closed_count: u64 = 0,
    packets_out_call_count: u64 = 0,
    packets_out_sent_count: u64 = 0,
    packets_out_eagain_count: u64 = 0,
    packets_out_error_count: u64 = 0,
    has_unsent_retry_count: u64 = 0,
};

const DebugCounters = struct {
    timer_immediate_count: std.atomic.Value(u64) = .init(0),
    timer_timeout_count: std.atomic.Value(u64) = .init(0),
    timer_indefinite_count: std.atomic.Value(u64) = .init(0),
    current_consecutive_immediate_ticks: std.atomic.Value(u64) = .init(0),
    max_consecutive_immediate_ticks: std.atomic.Value(u64) = .init(0),
    advisory_tick_count: std.atomic.Value(u64) = .init(0),
    latest_advisory_diff_us: std.atomic.Value(i64) = .init(0),
    min_advisory_diff_us: std.atomic.Value(i64) = .init(std.math.maxInt(i64)),
    max_advisory_diff_us: std.atomic.Value(i64) = .init(std.math.minInt(i64)),
    process_engine_count: std.atomic.Value(u64) = .init(0),
    process_engine_reentrant_skip_count: std.atomic.Value(u64) = .init(0),
    process_engine_total_ns: std.atomic.Value(u64) = .init(0),
    process_engine_max_ns: std.atomic.Value(u64) = .init(0),
    on_read_count: std.atomic.Value(u64) = .init(0),
    on_read_bytes: std.atomic.Value(u64) = .init(0),
    on_read_would_block_count: std.atomic.Value(u64) = .init(0),
    on_read_zero_before_data_count: std.atomic.Value(u64) = .init(0),
    on_read_eof_count: std.atomic.Value(u64) = .init(0),
    read_queue_full_count: std.atomic.Value(u64) = .init(0),
    read_queue_closed_count: std.atomic.Value(u64) = .init(0),
    accept_queue_full_count: std.atomic.Value(u64) = .init(0),
    accept_queue_closed_count: std.atomic.Value(u64) = .init(0),
    packets_out_call_count: std.atomic.Value(u64) = .init(0),
    packets_out_sent_count: std.atomic.Value(u64) = .init(0),
    packets_out_eagain_count: std.atomic.Value(u64) = .init(0),
    packets_out_error_count: std.atomic.Value(u64) = .init(0),
    has_unsent_retry_count: std.atomic.Value(u64) = .init(0),
};

const zero_before_data_read_close_threshold = 64;

const ZeroBeforeDataAction = enum {
    retry,
    defensive_close,
};

fn zeroBeforeDataAction(spurious_read_count: u32) ZeroBeforeDataAction {
    return if (spurious_read_count >= zero_before_data_read_close_threshold) .defensive_close else .retry;
}

fn armReadOnNewStream(_: bool) bool {
    return false;
}

const ProcessWait = union(enum) {
    immediate,
    indefinite,
    timeout_us: i64,
};

fn counterInc(counter: *std.atomic.Value(u64)) void {
    _ = counter.fetchAdd(1, .monotonic);
}

fn counterAdd(counter: *std.atomic.Value(u64), amount: u64) void {
    _ = counter.fetchAdd(amount, .monotonic);
}

fn updateMax(counter: *std.atomic.Value(u64), value: u64) void {
    var current = counter.load(.monotonic);
    while (value > current) {
        current = counter.cmpxchgWeak(current, value, .monotonic, .monotonic) orelse return;
    }
}

fn updateAdvisoryStats(counters: *DebugCounters, diff: c_int) void {
    const value: i64 = @intCast(diff);
    counterInc(&counters.advisory_tick_count);
    counters.latest_advisory_diff_us.store(value, .monotonic);

    var min_current = counters.min_advisory_diff_us.load(.monotonic);
    while (value < min_current) {
        min_current = counters.min_advisory_diff_us.cmpxchgWeak(min_current, value, .monotonic, .monotonic) orelse break;
    }

    var max_current = counters.max_advisory_diff_us.load(.monotonic);
    while (value > max_current) {
        max_current = counters.max_advisory_diff_us.cmpxchgWeak(max_current, value, .monotonic, .monotonic) orelse break;
    }
}

fn monotonicNanoseconds() ?u64 {
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.MONOTONIC, &ts) != 0) return null;
        if (ts.sec < 0 or ts.nsec < 0) return null;
        return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }
    return null;
}

fn computeProcessWait(advisory_diff_us: ?c_int, has_unsent: bool) ProcessWait {
    if (advisory_diff_us) |diff| {
        if (diff <= 0) return .immediate;
        const advisory_us: i64 = @intCast(diff);
        if (has_unsent) {
            return .{ .timeout_us = @min(advisory_us, unsent_retry_interval_ms * std.time.us_per_ms) };
        }
        return .{ .timeout_us = advisory_us };
    }
    if (has_unsent) {
        return .{ .timeout_us = unsent_retry_interval_ms * std.time.us_per_ms };
    }
    return .indefinite;
}

fn timeoutFromMicroseconds(us: i64) Io.Timeout {
    return .{ .duration = .{
        .raw = Io.Duration.fromNanoseconds(@as(i96, us) * std.time.ns_per_us),
        .clock = .awake,
    } };
}

fn receiveLoopBackoffMs(consecutive_errors: u32) u64 {
    if (consecutive_errors == 0) return 0;
    const shift: u6 = @intCast(@min(consecutive_errors - 1, 63));
    return @min(@as(u64, 1) << shift, 100);
}

fn shouldLogReceiveError(consecutive_errors: u32) bool {
    return consecutive_errors <= 3 or std.math.isPowerOfTwo(consecutive_errors);
}

fn isTerminalReceiveError(err: net.Socket.ReceiveError) bool {
    return switch (err) {
        error.SocketUnconnected => true,
        else => false,
    };
}

fn sleepMilliseconds(io: Io, ms: u64) Io.Cancelable!void {
    if (ms == 0) return;
    const timeout: Io.Timeout = .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(@intCast(ms)),
        .clock = .awake,
    } };
    try timeout.sleep(io);
}

// ── QuicStream ─────────────────────────────────────────────────────────

/// QUIC stream backed by lsquic. Reads/writes suspend via Io.Queue.
pub const QuicStream = struct {
    allocator: Allocator,
    lsquic_stream: ?*lsquic.lsquic_stream_t,
    conn: *QuicConnection,
    io: Io,
    read_queue_buf: [stream_read_queue_capacity]ReadEvent,
    read_queue: Io.Queue(ReadEvent),
    write_queue_buf: [1]WriteEvent,
    write_queue: Io.Queue(WriteEvent),
    has_received_data: bool,
    spurious_read_count: u32,
    closed: bool,
    read_closed: bool,
    write_closed: bool,
    counted_on_conn: bool,
    shutdown_started: std.atomic.Value(bool),
    queued_ref_active: std.atomic.Value(bool),
    user_ref_active: std.atomic.Value(bool),
    ref_count: std.atomic.Value(usize),
    /// Leftover data from a previous ReadEvent when caller's buffer was too small.
    leftover_buf: ?[]u8 = null,
    leftover_offset: usize = 0,

    pub fn init(allocator: Allocator, ls: *lsquic.lsquic_stream_t, conn: *QuicConnection) !*QuicStream {
        const self = try allocator.create(QuicStream);
        self.* = .{
            .allocator = allocator,
            .lsquic_stream = ls,
            .conn = conn,
            .io = conn.io,
            .read_queue_buf = undefined,
            .read_queue = undefined,
            .write_queue_buf = undefined,
            .write_queue = undefined,
            .has_received_data = false,
            .spurious_read_count = 0,
            .closed = false,
            .read_closed = false,
            .write_closed = false,
            .counted_on_conn = false,
            .shutdown_started = .init(false),
            .queued_ref_active = .init(false),
            .user_ref_active = .init(false),
            .ref_count = .init(1),
        };
        self.read_queue = Io.Queue(ReadEvent).init(&self.read_queue_buf);
        self.write_queue = Io.Queue(WriteEvent).init(&self.write_queue_buf);
        lsquic.lsquic_stream_set_ctx(ls, @ptrCast(self));
        return self;
    }

    pub fn read(self: *QuicStream, io: Io, buf: []u8) anyerror!usize {
        // Serve from leftover data first — even if the stream is closed,
        // there may be buffered data to return.
        if (self.leftover_buf) |lb| {
            const stream_id_for_log = if (self.lsquic_stream) |ls2| lsquic.lsquic_stream_id(ls2) else @as(u64, 999);
            _ = stream_id_for_log;
            const remaining = lb.len - self.leftover_offset;
            const len = @min(buf.len, remaining);
            @memcpy(buf[0..len], lb[self.leftover_offset..][0..len]);
            if (len == remaining) {
                // Consumed all leftover data, free the buffer
                self.allocator.free(lb);
                self.leftover_buf = null;
                self.leftover_offset = 0;
            } else {
                self.leftover_offset += len;
            }
            return len;
        }

        if (self.read_closed) return error.StreamClosed;

        if (self.closed) {
            log.warn("read: stream closed, no leftover data (has_received={}, lsquic={?*})", .{
                self.has_received_data, self.lsquic_stream,
            });
            return error.StreamClosed;
        }

        // Arm the lsquic read callback — tells lsquic to call onRead when
        // data is available. Must be done lazily (not in onNewStream) to avoid
        // false EOF when onRead fires before STREAM frames are processed.
        self.conn.engine.lockLsquic();
        if (self.lsquic_stream) |ls| {
            _ = lsquic.lsquic_stream_wantread(ls, 1);
        }
        self.conn.engine.unlockLsquic();
        const event = self.read_queue.getOne(io) catch |err| switch (err) {
            error.Closed => return 0, // EOF — peer closed the stream
            error.Canceled => return error.StreamClosed,
        };
        const len = @min(buf.len, event.data.len);
        @memcpy(buf[0..len], event.data[0..len]);
        if (len < event.data.len) {
            // Partial read — save remaining data for next read call
            self.leftover_buf = event.owned_buf;
            self.leftover_offset = len;
        } else {
            // Consumed everything, free immediately
            self.allocator.free(event.owned_buf);
        }
        return len;
    }

    pub fn write(self: *QuicStream, io: Io, data: []const u8) anyerror!usize {
        if (self.closed or self.write_closed or self.conn.closed) return error.StreamClosed;
        if (data.len == 0) return 0;

        while (true) {
            self.conn.engine.lockLsquic();
            const ls = self.lsquic_stream orelse {
                self.conn.engine.unlockLsquic();
                return error.StreamClosed;
            };
            const written = lsquic.lsquic_stream_write(ls, data.ptr, data.len);
            if (written > 0) {
                _ = lsquic.lsquic_stream_flush(ls);
                if (@as(usize, @intCast(written)) < data.len) {
                    _ = lsquic.lsquic_stream_wantwrite(ls, 1);
                }
                self.conn.engine.requestProcessWake();
                self.conn.engine.unlockLsquic();
                return @intCast(written);
            }
            if (written < 0) {
                self.conn.engine.unlockLsquic();
                return error.WriteFailed;
            }
            _ = lsquic.lsquic_stream_wantwrite(ls, 1);
            self.conn.engine.requestProcessWake();
            self.conn.engine.unlockLsquic();
            try self.waitWriteReady(io);
        }
    }

    fn waitWriteReady(self: *QuicStream, io: Io) anyerror!void {
        if (self.closed or self.write_closed or self.conn.closed) return error.StreamClosed;
        _ = self.write_queue.getOne(io) catch |err| switch (err) {
            error.Closed => return error.StreamClosed,
            error.Canceled => return error.StreamClosed,
        };
    }

    fn signalWriteReady(self: *QuicStream) void {
        _ = tryQueueOneUncancelable(WriteEvent, &self.write_queue, self.io, .ready) catch {};
    }

    pub fn closeRead(self: *QuicStream, _: Io) void {
        if (self.read_closed) return;
        self.read_closed = true;
        self.conn.engine.lockLsquic();
        if (self.lsquic_stream) |ls| {
            if (!self.conn.closed) {
                _ = lsquic.lsquic_stream_shutdown(ls, 0);
                _ = lsquic.lsquic_stream_wantread(ls, 0);
                self.conn.engine.requestProcessWake();
            }
        }
        self.conn.engine.unlockLsquic();
        self.read_queue.close(self.io);
    }

    pub fn closeWrite(self: *QuicStream, _: Io) void {
        if (self.write_closed) return;
        self.write_closed = true;
        self.conn.engine.lockLsquic();
        if (self.lsquic_stream) |ls| {
            if (!self.conn.closed) {
                _ = lsquic.lsquic_stream_shutdown(ls, 1);
                self.conn.engine.requestProcessWake();
            }
        }
        self.conn.engine.unlockLsquic();
        self.write_queue.close(self.io);
    }

    pub fn close(self: *QuicStream, _: Io) void {
        if (self.shutdown_started.load(.acquire)) return;
        self.beginShutdown();
        self.conn.engine.lockLsquic();
        if (self.lsquic_stream) |ls| {
            // Tell lsquic to close the stream. Ownership remains with the caller,
            // which must later call deinit() once it is done with the wrapper.
            if (!self.conn.closed) {
                _ = lsquic.lsquic_stream_close(ls);
                self.conn.engine.requestProcessWake();
            }
        }
        self.conn.engine.unlockLsquic();
        self.read_queue.close(self.io);
        self.write_queue.close(self.io);
    }

    pub fn deinit(self: *QuicStream) void {
        self.retainRef();
        defer self.releaseRef();
        // Only for manual cleanup when onStreamClose won't fire (e.g. error paths before lsquic knows about the stream)
        self.beginShutdown();
        var released_lsquic_ref = false;
        self.conn.engine.lockLsquic();
        if (self.lsquic_stream) |ls| {
            lsquic.lsquic_stream_set_ctx(ls, null);
            if (!self.conn.closed) {
                _ = lsquic.lsquic_stream_close(ls);
                self.conn.engine.requestProcessWake();
            }
            self.lsquic_stream = null;
            released_lsquic_ref = true;
        }
        self.conn.engine.unlockLsquic();
        if (released_lsquic_ref) {
            self.releaseRef();
        }
        if (self.user_ref_active.swap(false, .acq_rel)) {
            self.releaseRef();
        }
        if (self.queued_ref_active.swap(false, .acq_rel)) {
            self.releaseRef();
        }
    }

    fn markActive(self: *QuicStream) void {
        if (self.counted_on_conn) return;
        self.counted_on_conn = true;
        if (!self.user_ref_active.swap(true, .acq_rel)) {
            self.retainRef();
        }
        if (self.queued_ref_active.swap(false, .acq_rel)) {
            self.releaseRef();
        }
        self.conn.retainActiveStream();
    }

    fn markQueued(self: *QuicStream) void {
        if (self.queued_ref_active.swap(true, .acq_rel)) return;
        self.retainRef();
    }

    fn closeNoLock(self: *QuicStream) void {
        self.beginShutdown();
        if (self.lsquic_stream) |ls| {
            if (!self.conn.closed) {
                _ = lsquic.lsquic_stream_close(ls);
            }
        }
    }

    fn destroyRejectedNoLock(self: *QuicStream) void {
        self.beginShutdown();
        if (self.lsquic_stream) |ls| {
            lsquic.lsquic_stream_set_ctx(ls, null);
            if (!self.conn.closed) {
                _ = lsquic.lsquic_stream_close(ls);
            }
            self.lsquic_stream = null;
            self.releaseRef();
        }
        if (self.queued_ref_active.swap(false, .acq_rel)) {
            self.releaseRef();
        }
    }

    fn retainRef(self: *QuicStream) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    fn releaseRef(self: *QuicStream) void {
        var current = self.ref_count.load(.acquire);
        while (true) {
            if (current == 0) {
                log.err("QuicStream releaseRef underflow", .{});
                return;
            }
            if (self.ref_count.cmpxchgWeak(current, current - 1, .acq_rel, .acquire)) |observed| {
                current = observed;
                continue;
            }
            if (current == 1) {
                self.finalizeDestroy();
            }
            return;
        }
    }

    fn beginShutdown(self: *QuicStream) void {
        if (self.shutdown_started.swap(true, .acq_rel)) return;
        self.closed = true;
        self.read_closed = true;
        self.write_closed = true;
        self.read_queue.close(self.io);
        self.write_queue.close(self.io);
    }

    fn finalizeDestroy(self: *QuicStream) void {
        self.beginShutdown();
        self.drainReadQueue();
        self.drainWriteQueue();
        if (self.leftover_buf) |lb| {
            self.allocator.free(lb);
        }
        if (self.counted_on_conn) {
            self.conn.releaseActiveStream();
        }
        self.allocator.destroy(self);
    }

    fn drainReadQueue(self: *QuicStream) void {
        var events: [16]ReadEvent = undefined;
        while (true) {
            const count = self.read_queue.getUncancelable(self.io, &events, 0) catch |err| switch (err) {
                error.Closed => break,
            };
            if (count == 0) break;
            for (events[0..count]) |event| {
                self.allocator.free(event.owned_buf);
            }
        }
    }

    fn drainWriteQueue(self: *QuicStream) void {
        var events: [1]WriteEvent = undefined;
        while (true) {
            const count = self.write_queue.getUncancelable(self.io, &events, 0) catch |err| switch (err) {
                error.Closed => break,
            };
            if (count == 0) break;
        }
    }
};

/// Keeps a QUIC stream alive for the duration of an inbound task even after
/// ownership of the cleanup path has been promoted elsewhere.
pub const StreamTaskLease = struct {
    inner: ?*QuicStream,

    pub fn init(inner: *QuicStream) StreamTaskLease {
        inner.retainRef();
        return .{ .inner = inner };
    }

    pub fn read(self: *StreamTaskLease, io: Io, buf: []u8) anyerror!usize {
        return self.borrowInner().read(io, buf);
    }

    pub fn write(self: *StreamTaskLease, io: Io, data: []const u8) anyerror!usize {
        return self.borrowInner().write(io, data);
    }

    pub fn closeRead(self: *StreamTaskLease, io: Io) void {
        self.borrowInner().closeRead(io);
    }

    pub fn closeWrite(self: *StreamTaskLease, io: Io) void {
        self.borrowInner().closeWrite(io);
    }

    pub fn close(self: *StreamTaskLease, io: Io) void {
        self.borrowInner().close(io);
    }

    pub fn deinit(self: *StreamTaskLease) void {
        const inner = self.takeInner() orelse return;
        inner.releaseRef();
    }

    fn borrowInner(self: *StreamTaskLease) *QuicStream {
        return self.inner orelse unreachable;
    }

    fn takeInner(self: *StreamTaskLease) ?*QuicStream {
        const inner = self.inner;
        self.inner = null;
        return inner;
    }
};

// ── QuicConnection ─────────────────────────────────────────────────────

/// Signal pushed by `onHskDone` to wake up `waitHandshake`.
pub const HandshakeResult = enum { ok, failed };

/// QUIC connection backed by lsquic. Stream accept/open via Io.Queue.
pub const QuicConnection = struct {
    allocator: Allocator,
    lsquic_conn: ?*lsquic.lsquic_conn_t,
    engine: *QuicEngine,
    io: Io,
    stream_queue_buf: [16]StreamEvent,
    stream_queue: Io.Queue(StreamEvent),
    outbound_stream_queue_buf: [16]StreamEvent,
    outbound_stream_queue: Io.Queue(StreamEvent),
    hsk_queue_buf: [1]HandshakeResult,
    hsk_queue: Io.Queue(HandshakeResult),
    peer_id: ?PeerId,
    hsk_completed: bool,
    closed: bool,
    ref_count: std.atomic.Value(usize),

    pub fn init(allocator: Allocator, lc: ?*lsquic.lsquic_conn_t, engine: *QuicEngine) !*QuicConnection {
        const self = try allocator.create(QuicConnection);
        self.* = .{
            .allocator = allocator,
            .lsquic_conn = lc,
            .engine = engine,
            .io = engine.io,
            .stream_queue_buf = undefined,
            .stream_queue = undefined,
            .outbound_stream_queue_buf = undefined,
            .outbound_stream_queue = undefined,
            .hsk_queue_buf = undefined,
            .hsk_queue = undefined,
            .peer_id = null,
            .hsk_completed = false,
            .closed = false,
            .ref_count = .init(1),
        };
        self.stream_queue = Io.Queue(StreamEvent).init(&self.stream_queue_buf);
        self.outbound_stream_queue = Io.Queue(StreamEvent).init(&self.outbound_stream_queue_buf);
        self.hsk_queue = Io.Queue(HandshakeResult).init(&self.hsk_queue_buf);
        if (lc) |c| lsquic.lsquic_conn_set_ctx(c, @ptrCast(self));
        return self;
    }

    pub fn openStream(self: *QuicConnection, io: Io) !*QuicStream {
        self.engine.lockLsquic();
        const queued_open = blk: {
            // Re-read connection state under the lsquic lock so a concurrent
            // onConnClosed callback cannot leave us with a stale conn pointer.
            if (self.closed) break :blk false;
            const lc = self.lsquic_conn orelse break :blk false;

            const status = lsquic.lsquic_conn_status(lc, null, 0);
            switch (status) {
                lsquic.LSCONN_ST_CONNECTED => {},
                else => break :blk false,
            }

            lsquic.lsquic_conn_make_stream(lc);
            self.engine.requestProcessWake();
            break :blk true;
        };
        self.engine.unlockLsquic();
        if (!queued_open) return error.ConnectionClosed;
        // Let the background timer loop call processEngine to create the stream
        // via onNewStream. Calling processEngine synchronously here can crash
        // inside lsquic's SSL post-handshake processing when the crypto stream
        // has pending events and the SSL session state is still settling.
        // The suspend on outbound_stream_queue.getOne yields to the background loops.
        // Wait for the stream event from onNewStream callback
        const event = self.outbound_stream_queue.getOne(io) catch |err| switch (err) {
            error.Closed => return error.ConnectionClosed,
            error.Canceled => return error.ConnectionClosed,
        };
        event.stream.markActive();
        return event.stream;
    }

    pub fn acceptStream(self: *QuicConnection, io: Io) !*QuicStream {
        if (self.closed) return error.ConnectionClosed;
        const event = self.stream_queue.getOne(io) catch |err| switch (err) {
            error.Closed => return error.ConnectionClosed,
            error.Canceled => return error.ConnectionClosed,
        };
        event.stream.markActive();
        return event.stream;
    }

    pub fn close(self: *QuicConnection, io: Io) void {
        _ = io;
        self.engine.lockLsquic();
        if (self.lsquic_conn) |lc| {
            // Clear conn context before closing so lsquic doesn't assert on destroy
            lsquic.lsquic_conn_set_ctx(lc, null);
            lsquic.lsquic_conn_close(lc);
            self.lsquic_conn = null;
            self.engine.requestProcessWake();
        }
        self.engine.unlockLsquic();
        self.closed = true;
        self.stream_queue.close(self.io);
        self.outbound_stream_queue.close(self.io);
        self.hsk_queue.close(self.io);
    }

    pub fn remotePeerId(self: *const QuicConnection) ?PeerId {
        return self.peer_id;
    }

    pub fn remoteIpAddress(self: *const QuicConnection) ?net.IpAddress {
        self.engine.lockLsquic();
        defer self.engine.unlockLsquic();
        const lc = self.lsquic_conn orelse return null;
        var local_sa: ?*const std.c.sockaddr = null;
        var peer_sa: ?*const std.c.sockaddr = null;
        if (lsquic.lsquic_conn_get_sockaddr(lc, @ptrCast(&local_sa), @ptrCast(&peer_sa)) != 0) {
            return null;
        }
        const sa = peer_sa orelse return null;
        return sockaddrToIpAddress(sa);
    }

    pub fn localIpAddress(self: *const QuicConnection) ?net.IpAddress {
        self.engine.lockLsquic();
        defer self.engine.unlockLsquic();
        const lc = self.lsquic_conn orelse return null;
        var local_sa: ?*const std.c.sockaddr = null;
        var peer_sa: ?*const std.c.sockaddr = null;
        if (lsquic.lsquic_conn_get_sockaddr(lc, @ptrCast(&local_sa), @ptrCast(&peer_sa)) != 0) {
            return null;
        }
        const sa = local_sa orelse return null;
        return sockaddrToIpAddress(sa);
    }

    /// Suspend until the TLS handshake completes (or fails).
    /// Returns the verified remote peer ID on success.
    pub fn waitHandshake(self: *QuicConnection, io: Io) !PeerId {
        // If already completed (e.g. server path), return immediately
        if (self.hsk_completed) {
            return self.peer_id orelse error.HandshakeFailed;
        }
        const result = self.hsk_queue.getOne(io) catch |err| switch (err) {
            error.Closed => return error.HandshakeFailed,
            error.Canceled => return error.HandshakeFailed,
        };
        return switch (result) {
            .ok => self.peer_id orelse error.HandshakeFailed,
            .failed => error.HandshakeFailed,
        };
    }

    pub fn deinit(self: *QuicConnection) void {
        self.engine.lockLsquic();
        if (self.lsquic_conn) |lc| {
            lsquic.lsquic_conn_set_ctx(lc, null);
            lsquic.lsquic_conn_close(lc);
            self.lsquic_conn = null;
        }
        self.engine.unlockLsquic();
        self.closed = true;
        self.stream_queue.close(self.io);
        self.outbound_stream_queue.close(self.io);
        self.hsk_queue.close(self.io);
        self.releaseRef();
    }

    fn retainActiveStream(self: *QuicConnection) void {
        self.retainRef();
    }

    pub fn retainBorrow(self: *QuicConnection) void {
        self.retainRef();
    }

    fn releaseActiveStream(self: *QuicConnection) void {
        self.releaseRef();
    }

    pub fn releaseBorrow(self: *QuicConnection) void {
        self.releaseRef();
    }

    fn retainRef(self: *QuicConnection) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    fn releaseRef(self: *QuicConnection) void {
        var current = self.ref_count.load(.acquire);
        while (true) {
            if (current == 0) {
                log.err("QuicConnection releaseRef underflow", .{});
                return;
            }
            if (self.ref_count.cmpxchgWeak(current, current - 1, .acq_rel, .acquire)) |observed| {
                current = observed;
                continue;
            }
            if (current == 1) self.finalizeDestroy();
            return;
        }
    }

    fn finalizeDestroy(self: *QuicConnection) void {
        self.drainStreamQueues();
        self.allocator.destroy(self);
    }

    fn drainStreamQueues(self: *QuicConnection) void {
        var stream_events: [16]StreamEvent = undefined;
        while (true) {
            const count = self.stream_queue.getUncancelable(self.io, &stream_events, 0) catch |err| switch (err) {
                error.Closed => break,
            };
            if (count == 0) break;
            for (stream_events[0..count]) |event| {
                event.stream.deinit();
            }
        }

        while (true) {
            const count = self.outbound_stream_queue.getUncancelable(self.io, &stream_events, 0) catch |err| switch (err) {
                error.Closed => break,
            };
            if (count == 0) break;
            for (stream_events[0..count]) |event| {
                event.stream.deinit();
            }
        }

        var hsk_events: [1]HandshakeResult = undefined;
        while (true) {
            const count = self.hsk_queue.getUncancelable(self.io, &hsk_events, 0) catch |err| switch (err) {
                error.Closed => break,
            };
            if (count == 0) break;
        }
    }
};

// ── CertVerifyCtx ──────────────────────────────────────────────────────

/// Replaces the threadlocal g_peer_cert hack. Stores verified peer info
/// keyed by the concrete lsquic connection pointer associated with the TLS
/// session being verified.
pub const CertVerifyCtx = struct {
    allocator: Allocator,
    verified_by_conn: std.AutoHashMap(usize, VerifiedPeer),
    pending_server_verified: std.ArrayList(VerifiedPeer),
    pending_server_head: usize,

    pub const VerifiedPeer = struct {
        peer_id: PeerId,
        host_pubkey: keys.PublicKey,
    };

    pub fn init(allocator: Allocator) CertVerifyCtx {
        return .{
            .allocator = allocator,
            .verified_by_conn = std.AutoHashMap(usize, VerifiedPeer).init(allocator),
            .pending_server_verified = .empty,
            .pending_server_head = 0,
        };
    }

    pub fn deinit(self: *CertVerifyCtx) void {
        var iter = self.verified_by_conn.valueIterator();
        while (iter.next()) |vp| {
            if (vp.host_pubkey.data) |d| self.allocator.free(d);
        }
        self.verified_by_conn.deinit();
        while (self.pending_server_head < self.pending_server_verified.items.len) : (self.pending_server_head += 1) {
            const vp = self.pending_server_verified.items[self.pending_server_head];
            if (vp.host_pubkey.data) |d| self.allocator.free(d);
        }
        self.pending_server_verified.deinit(self.allocator);
    }

    fn connCtxKey(conn_ctx: *anyopaque) usize {
        return @intFromPtr(conn_ctx);
    }

    fn compactPendingServer(self: *CertVerifyCtx) void {
        if (self.pending_server_head == 0) return;
        if (self.pending_server_head == self.pending_server_verified.items.len) {
            self.pending_server_verified.clearRetainingCapacity();
            self.pending_server_head = 0;
            return;
        }
        var compacted: std.ArrayList(VerifiedPeer) = .empty;
        compacted.appendSlice(self.allocator, self.pending_server_verified.items[self.pending_server_head..]) catch return;
        self.pending_server_verified.deinit(self.allocator);
        self.pending_server_verified = compacted;
        self.pending_server_head = 0;
    }

    pub fn storeVerified(
        self: *CertVerifyCtx,
        conn_ctx: ?*anyopaque,
        is_server: bool,
        peer: VerifiedPeer,
    ) !void {
        if (is_server) {
            try self.pending_server_verified.append(self.allocator, peer);
            return;
        }
        const ctx = conn_ctx orelse return error.MissingConnContext;
        const gop = try self.verified_by_conn.getOrPut(connCtxKey(ctx));
        if (gop.found_existing) {
            if (gop.value_ptr.host_pubkey.data) |d| self.allocator.free(d);
        }
        gop.value_ptr.* = peer;
    }

    pub fn takeVerified(self: *CertVerifyCtx, conn_ctx: ?*anyopaque) ?VerifiedPeer {
        if (conn_ctx == null) return null;
        return if (self.verified_by_conn.fetchRemove(connCtxKey(conn_ctx.?))) |entry|
            entry.value
        else
            null;
    }

    pub fn discardVerified(self: *CertVerifyCtx, conn_ctx: ?*anyopaque) void {
        if (conn_ctx == null) return;
        if (self.verified_by_conn.fetchRemove(connCtxKey(conn_ctx.?))) |entry| {
            if (entry.value.host_pubkey.data) |d| self.allocator.free(d);
        }
    }

    pub fn takeNextServerVerified(self: *CertVerifyCtx) ?VerifiedPeer {
        if (self.pending_server_head >= self.pending_server_verified.items.len) return null;
        const result = self.pending_server_verified.items[self.pending_server_head];
        self.pending_server_head += 1;
        self.compactPendingServer();
        return result;
    }
};

// ── QuicEngine ─────────────────────────────────────────────────────────

/// Bridges lsquic's C callback model with Zig's std.Io suspension model.
///
/// The engine owns one or more UDP sockets, the lsquic_engine_t, and manages the
/// lifecycle of connections and streams. It runs two concurrent tasks:
///   1. UDP receive loop: reads datagrams -> feeds to lsquic
///   2. Engine process loop: timer-driven lsquic_engine_process_conns()
///
/// lsquic callbacks (stream_if) push events into per-connection/per-stream
/// Io.Queue instances. Application code suspends on these queues.
pub const QuicEngine = struct {
    allocator: Allocator,
    engine: *lsquic.lsquic_engine_t,
    ssl_ctx: *ssl.SSL_CTX,
    cert_verify_ctx: CertVerifyCtx,
    conn_queue_buf: [16]ConnEvent,
    conn_queue: Io.Queue(ConnEvent),
    socket: ?net.Socket,
    sockets: std.ArrayList(net.Socket),
    bound_addrs: std.ArrayList(net.IpAddress),
    io: Io,
    is_server: bool,
    running: bool,
    has_unsent: bool,
    process_wake: Io.Event,
    lsquic_mutex: Io.Mutex,
    /// Server-side connection pending to be pushed to conn_queue.
    /// Set in onNewConn callback (which runs inside lsquic_engine_process_conns),
    /// consumed by processEngine() after lsquic returns to avoid re-entrancy.
    pending_server_conn: ?*QuicConnection,

    /// Guard against re-entrant calls to lsquic_engine_process_conns.
    processing: std.atomic.Value(bool),

    /// Background task group for receive and timer loops.
    /// Owned by the engine so it outlives the stack frames that spawn the loops.
    background: Io.Group,

    /// Behavior-preserving instrumentation for QUIC runtime diagnostics.
    debug: DebugCounters,

    // lsquic callback vtables (must be stable pointers)
    stream_if: lsquic.lsquic_stream_if,

    pub const Config = struct {
        is_server: bool = false,
        alpn: [:0]const u8 = "libp2p",
        max_streams_per_conn: u32 = 100,
        idle_timeout_secs: u32 = 30,
        /// Optional QUIC/TLS handshake timeout for client connections.
        /// lsquic expects this value in microseconds; `null` keeps lsquic's
        /// default transport-level timeout.
        handshake_timeout_ms: ?u64 = null,
        /// libp2p host identity used to sign the libp2p TLS extension.
        /// The engine always generates its own TLS subject key internally.
        host_identity: ?*const identity.KeyPair = null,
    };

    pub fn init(allocator: Allocator, io: Io, config: Config) !*QuicEngine {
        // Initialize lsquic global state (safe to call multiple times)
        if (lsquic.lsquic_global_init(lsquic.LSQUIC_GLOBAL_CLIENT | lsquic.LSQUIC_GLOBAL_SERVER) != 0) {
            return error.LsquicGlobalInitFailed;
        }

        // Enable lsquic internal logging for diagnostics
        const logger_if = lsquic.lsquic_logger_if{
            .log_buf = struct {
                fn cb(_: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
                    if (buf != null and len > 0) {
                        log.debug("[lsquic] {s}", .{buf[0..len]});
                    }
                    return 0;
                }
            }.cb,
        };
        lsquic.lsquic_logger_init(&logger_if, null, lsquic.LLTS_HHMMSSMS);
        _ = lsquic.lsquic_set_log_level("warning");

        const self = try allocator.create(QuicEngine);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.cert_verify_ctx = CertVerifyCtx.init(allocator);
        self.conn_queue_buf = undefined;
        self.socket = null;
        self.sockets = .empty;
        self.bound_addrs = .empty;
        self.io = io;
        self.is_server = config.is_server;
        self.running = false;
        self.has_unsent = false;
        self.process_wake = .unset;
        self.lsquic_mutex = .init;
        self.processing = .init(false);
        self.pending_server_conn = null;
        self.background = .init;
        self.debug = .{};

        self.conn_queue = Io.Queue(ConnEvent).init(&self.conn_queue_buf);

        // Build the stream interface callbacks
        self.stream_if = std.mem.zeroes(lsquic.lsquic_stream_if);
        self.stream_if.on_new_conn = onNewConn;
        self.stream_if.on_conn_closed = onConnClosed;
        self.stream_if.on_new_stream = onNewStream;
        self.stream_if.on_read = onRead;
        self.stream_if.on_write = onWrite;
        self.stream_if.on_close = onStreamClose;
        self.stream_if.on_hsk_done = onHskDone;
        self.stream_if.on_conncloseframe_received = onConnCloseFrame;

        // Create SSL context
        self.ssl_ctx = ssl.SSL_CTX_new(ssl.TLS_method()) orelse return error.SslCtxCreateFailed;

        // QUIC requires TLS 1.3 — pin the protocol version.
        // Without this, BoringSSL may negotiate TLS 1.2, causing HKDF digest
        // size mismatches (assertion failure in hkdf_extract_to_secret).
        // Matches lsquic's own SSL_CTX setup in lsquic_enc_sess_ietf.c.
        if (ssl.SSL_CTX_set_min_proto_version(self.ssl_ctx, @intCast(ssl.TLS1_3_VERSION)) == 0)
            return error.SslCtxCreateFailed;
        if (ssl.SSL_CTX_set_max_proto_version(self.ssl_ctx, @intCast(ssl.TLS1_3_VERSION)) == 0)
            return error.SslCtxCreateFailed;

        // Initialize the global SSL_CTX ex_data index on first engine creation
        if (g_ssl_ctx_ex_idx == -1) {
            g_ssl_ctx_ex_idx = ssl.SSL_CTX_get_ex_new_index(0, null, null, null, null);
            if (g_ssl_ctx_ex_idx < 0) return error.SslCtxCreateFailed;
        }

        // Configure ALPN for both client and server
        // ALPN wire format: <len><proto> — e.g. \x06libp2p
        const alpn_wire = [_]u8{ 6, 'l', 'i', 'b', 'p', '2', 'p' };
        if (ssl.SSL_CTX_set_alpn_protos(self.ssl_ctx, &alpn_wire, alpn_wire.len) != 0) {
            return error.AlpnSetupFailed;
        }
        ssl.SSL_CTX_set_alpn_select_cb(self.ssl_ctx, tls.alpnSelectCallbackfn, null);

        // Store CertVerifyCtx in SSL_CTX ex_data so the custom verify callback
        // can access it without threadlocal storage (nim-libp2p approach, lsquic#579).
        if (ssl.SSL_CTX_set_ex_data(self.ssl_ctx, g_ssl_ctx_ex_idx, @ptrCast(&self.cert_verify_ctx)) == 0) {
            return error.SslCtxCreateFailed;
        }

        // Register BoringSSL custom verify callback for mutual TLS.
        // This replaces SSL_CTX_set_verify + threadlocal g_peer_cert approach.
        // Works for both client and server since getSslCtx is called for both sides.
        ssl.SSL_CTX_set_custom_verify(
            self.ssl_ctx,
            ssl.SSL_VERIFY_PEER | ssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            customVerifyCallback,
        );

        // Load libp2p TLS certificate if a host identity is provided.
        if (config.host_identity) |host_identity| {
            const subject_key = tls.generateKeyPair(.ECDSA) catch return error.KeyGenFailed;
            defer ssl.EVP_PKEY_free(subject_key);

            var host_pubkey = host_identity.publicKey(allocator) catch
                return error.KeyEncodeFailed;
            defer if (host_pubkey.data) |d| allocator.free(d);

            const cert = tls.buildCert(
                allocator,
                &host_pubkey,
                @ptrCast(@constCast(host_identity)),
                identity.signWithKeyPair,
                subject_key,
            ) catch return error.CertBuildFailed;
            defer ssl.X509_free(cert);

            if (tls.x509ToPem(allocator, cert)) |pem| {
                defer allocator.free(pem);
                log.debug("Generated TLS cert:\n{s}", .{pem});
            } else |_| {}

            if (ssl.SSL_CTX_use_certificate(self.ssl_ctx, cert) <= 0)
                return error.CertLoadFailed;
            if (ssl.SSL_CTX_use_PrivateKey(self.ssl_ctx, subject_key) <= 0)
                return error.KeyLoadFailed;
        }

        // Configure engine settings
        var settings: lsquic.lsquic_engine_settings = undefined;
        lsquic.lsquic_engine_init_settings(&settings, if (config.is_server) lsquic.LSENG_SERVER else 0);
        settings.es_init_max_streams_bidi = config.max_streams_per_conn;
        settings.es_idle_timeout = config.idle_timeout_secs;
        settings.es_versions = (1 << lsquic.LSQVER_I001); // QUIC v1 (RFC 9000) only — avoids version negotiation with peers that don't support v2/drafts
        settings.es_cc_algo = 2; // BBR congestion control (faster ramp-up than default Cubic)
        settings.es_scid_iss_rate = 180; // Disable SCID issuance rate limiting
        settings.es_rw_once = 1; // Dispatch onRead/onWrite once per process_conns tick — prevents tight callback loops on streams with no data yet

        // Flow control for remote-initiated bidi streams. lsquic defaults to
        // 0 for the client, which means the server can't send any data on
        // streams it opens (Status, Ping, Metadata requests). Set to 1 MB.
        settings.es_init_max_stream_data_bidi_remote = 1 * 1024 * 1024;
        if (config.handshake_timeout_ms) |timeout_ms| {
            settings.es_handshake_to = timeout_ms * std.time.us_per_ms;
        }

        // Build engine API
        var engine_api: lsquic.lsquic_engine_api = std.mem.zeroes(lsquic.lsquic_engine_api);
        engine_api.ea_settings = &settings;
        engine_api.ea_stream_if = &self.stream_if;
        engine_api.ea_stream_if_ctx = @ptrCast(self);
        engine_api.ea_packets_out = packetsOut;
        engine_api.ea_packets_out_ctx = @ptrCast(self);
        engine_api.ea_get_ssl_ctx = getSslCtx;
        // ea_verify_cert is not needed: lsquic only calls it via its internal
        // verify_server_cert_callback, which is only installed when lsquic creates
        // its own SSL_CTX (i.e., when ea_get_ssl_ctx is NULL). We provide our own
        // SSL_CTX with SSL_CTX_set_custom_verify registered.
        engine_api.ea_verify_cert = null;
        engine_api.ea_verify_ctx = null;
        engine_api.ea_alpn = config.alpn.ptr;

        const flags: c_uint = if (config.is_server) lsquic.LSENG_SERVER else 0;
        self.engine = lsquic.lsquic_engine_new(flags, &engine_api) orelse
            return error.EngineCreateFailed;

        return self;
    }

    pub fn deinit(self: *QuicEngine) void {
        if (self.pending_server_conn) |conn| {
            self.pending_server_conn = null;
            conn.deinit();
        }
        self.drainConnQueue();
        for (self.sockets.items) |sock| {
            sock.close(self.io);
        }
        self.sockets.deinit(self.allocator);
        self.bound_addrs.deinit(self.allocator);
        self.lockLsquic();
        lsquic.lsquic_engine_destroy(self.engine);
        self.unlockLsquic();
        ssl.SSL_CTX_free(self.ssl_ctx);
        self.cert_verify_ctx.deinit();
        self.allocator.destroy(self);
    }

    /// Return a coherent-enough snapshot of QUIC diagnostic counters.
    /// Counters are observational only: reading them does not alter engine behavior.
    pub fn debugStatsSnapshot(self: *QuicEngine) QuicDebugStats {
        const advisory_count = self.debug.advisory_tick_count.load(.monotonic);
        const latest_advisory_diff_us: ?i64 = if (advisory_count == 0) null else self.debug.latest_advisory_diff_us.load(.monotonic);
        const min_advisory_raw = self.debug.min_advisory_diff_us.load(.monotonic);
        const max_advisory_raw = self.debug.max_advisory_diff_us.load(.monotonic);
        return .{
            .timer_immediate_count = self.debug.timer_immediate_count.load(.monotonic),
            .timer_timeout_count = self.debug.timer_timeout_count.load(.monotonic),
            .timer_indefinite_count = self.debug.timer_indefinite_count.load(.monotonic),
            .current_consecutive_immediate_ticks = self.debug.current_consecutive_immediate_ticks.load(.monotonic),
            .max_consecutive_immediate_ticks = self.debug.max_consecutive_immediate_ticks.load(.monotonic),
            .advisory_tick_count = advisory_count,
            .latest_advisory_diff_us = latest_advisory_diff_us,
            .min_advisory_diff_us = if (advisory_count == 0 or min_advisory_raw == std.math.maxInt(i64)) null else min_advisory_raw,
            .max_advisory_diff_us = if (advisory_count == 0 or max_advisory_raw == std.math.minInt(i64)) null else max_advisory_raw,
            .process_engine_count = self.debug.process_engine_count.load(.monotonic),
            .process_engine_reentrant_skip_count = self.debug.process_engine_reentrant_skip_count.load(.monotonic),
            .process_engine_total_ns = self.debug.process_engine_total_ns.load(.monotonic),
            .process_engine_max_ns = self.debug.process_engine_max_ns.load(.monotonic),
            .on_read_count = self.debug.on_read_count.load(.monotonic),
            .on_read_bytes = self.debug.on_read_bytes.load(.monotonic),
            .on_read_would_block_count = self.debug.on_read_would_block_count.load(.monotonic),
            .on_read_zero_before_data_count = self.debug.on_read_zero_before_data_count.load(.monotonic),
            .on_read_eof_count = self.debug.on_read_eof_count.load(.monotonic),
            .read_queue_full_count = self.debug.read_queue_full_count.load(.monotonic),
            .read_queue_closed_count = self.debug.read_queue_closed_count.load(.monotonic),
            .accept_queue_full_count = self.debug.accept_queue_full_count.load(.monotonic),
            .accept_queue_closed_count = self.debug.accept_queue_closed_count.load(.monotonic),
            .packets_out_call_count = self.debug.packets_out_call_count.load(.monotonic),
            .packets_out_sent_count = self.debug.packets_out_sent_count.load(.monotonic),
            .packets_out_eagain_count = self.debug.packets_out_eagain_count.load(.monotonic),
            .packets_out_error_count = self.debug.packets_out_error_count.load(.monotonic),
            .has_unsent_retry_count = self.debug.has_unsent_retry_count.load(.monotonic),
        };
    }

    fn drainConnQueue(self: *QuicEngine) void {
        var events: [16]ConnEvent = undefined;
        while (true) {
            const count = self.conn_queue.getUncancelable(self.io, &events, 0) catch |err| switch (err) {
                error.Closed => break,
            };
            if (count == 0) break;
            for (events[0..count]) |event| {
                event.conn.deinit();
            }
        }
    }

    /// Accept a new QUIC connection (blocks until one arrives).
    pub fn accept(self: *QuicEngine, io: Io) !*QuicConnection {
        log.debug("accept: waiting for incoming connection...", .{});
        const event = self.conn_queue.getOne(io) catch |err| switch (err) {
            error.Closed => return error.EngineStopped,
            error.Canceled => return error.EngineStopped,
        };
        return event.conn;
    }

    /// Connect to a remote address.
    pub fn connect(
        self: *QuicEngine,
        io: Io,
        remote_addr: *const std.c.sockaddr,
        local_addr: *const std.c.sockaddr,
    ) !*QuicConnection {
        _ = io;
        log.debug("connect: initiating connection", .{});

        // Create QuicConnection wrapper first so we can pass it as conn_ctx
        // to lsquic_engine_connect. This prevents onNewConn from creating a
        // duplicate QuicConnection.
        const conn = try QuicConnection.init(self.allocator, null, self);
        errdefer conn.deinit();

        self.lockLsquic();
        const lc = lsquic.lsquic_engine_connect(
            self.engine,
            lsquic.LSQVER_I001, // QUIC v1 (RFC 9000)
            @ptrCast(local_addr),
            @ptrCast(remote_addr),
            @ptrCast(self), // peer_ctx
            @ptrCast(conn), // conn_ctx — our QuicConnection
            null, // hostname
            0, // base_plpmtu
            null, // sess_resume
            0, // sess_resume_len
            null, // token
            0, // token_len
        ) orelse {
            self.unlockLsquic();
            return error.ConnectFailed;
        };

        // Update the QuicConnection with the actual lsquic_conn_t
        conn.lsquic_conn = lc;
        lsquic.lsquic_conn_set_ctx(lc, @ptrCast(conn));
        self.unlockLsquic();

        // Tick the new connection immediately, but go through processEngine()
        // so connect() obeys the same re-entrancy guard as the background loops.
        self.processEngine();

        return conn;
    }

    pub fn stop(self: *QuicEngine, io: Io) void {
        self.running = false;
        self.conn_queue.close(io);
        // Cancel background receive and timer loops, then wait for them to finish
        self.background.cancel(io);
    }

    /// Start the background receive and timer loops.
    /// Must be called after bindSocket().
    pub fn startBackgroundLoops(self: *QuicEngine, io: Io) void {
        if (self.running) return;
        self.running = true;
        for (self.sockets.items) |sock| {
            self.background.async(io, QuicEngine.runReceiveLoop, .{ self, io, sock });
        }
        self.background.async(io, QuicEngine.runTimerLoop, .{ self, io });
    }

    /// Bind a UDP socket.
    /// The socket is managed by std.Io which handles blocking/non-blocking internally.
    /// For the C callback packetsOut, we use std.c.sendmsg directly which handles EAGAIN.
    pub fn bindSocket(self: *QuicEngine, io: Io, address: *const net.IpAddress) !net.IpAddress {
        const sock = try net.IpAddress.bind(address, io, .{ .mode = .dgram });
        errdefer sock.close(io);
        try self.sockets.append(self.allocator, sock);
        errdefer _ = self.sockets.pop();
        try self.bound_addrs.append(self.allocator, sock.address);
        errdefer _ = self.bound_addrs.pop();

        if (self.socket == null) {
            self.socket = sock;
        }
        if (self.running) {
            self.background.async(io, QuicEngine.runReceiveLoop, .{ self, io, sock });
        }
        return sock.address;
    }

    pub fn localAddr(self: *const QuicEngine) ?net.IpAddress {
        return if (self.bound_addrs.items.len > 0) self.bound_addrs.items[0] else null;
    }

    pub fn localAddrs(self: *const QuicEngine) []const net.IpAddress {
        return self.bound_addrs.items;
    }

    pub fn socketForFamily(self: *const QuicEngine, family: net.IpAddress.Family) ?net.Socket {
        for (self.sockets.items) |sock| {
            switch (sock.address) {
                .ip4 => if (family == .ip4) return sock,
                .ip6 => if (family == .ip6) return sock,
            }
        }
        return null;
    }

    /// Run the UDP receive loop: reads datagrams and feeds them to lsquic.
    /// This should be spawned via Group.async.
    pub fn runReceiveLoop(self: *QuicEngine, io: Io, sock: net.Socket) void {
        log.debug("runReceiveLoop started", .{});
        var consecutive_errors: u32 = 0;
        while (self.running) {
            var buf: [65535]u8 = undefined;
            const msg = sock.receive(io, &buf) catch |err| {
                switch (err) {
                    error.Canceled => {
                        log.debug("runReceiveLoop: receive canceled, exiting", .{});
                        return;
                    },
                    else => {
                        if (isTerminalReceiveError(err)) {
                            log.warn("runReceiveLoop: stopping receive loop after terminal socket error: {}", .{err});
                            return;
                        }
                        consecutive_errors +|= 1;
                        const backoff_ms = receiveLoopBackoffMs(consecutive_errors);
                        if (shouldLogReceiveError(consecutive_errors)) {
                            log.warn("runReceiveLoop: receive failed (attempt {d}, backoff {d}ms): {}", .{
                                consecutive_errors,
                                backoff_ms,
                                err,
                            });
                        }
                        sleepMilliseconds(io, backoff_ms) catch |sleep_err| switch (sleep_err) {
                            error.Canceled => return,
                        };
                        continue;
                    },
                }
            };

            consecutive_errors = 0;

            log.debug("runReceiveLoop: received {} bytes", .{msg.data.len});

            // Convert IpAddress to sockaddr for lsquic
            var local_sa = ipAddressToSockaddr(sock.address);
            var peer_sa = ipAddressToSockaddr(msg.from);

            self.lockLsquic();
            _ = lsquic.lsquic_engine_packet_in(
                self.engine,
                msg.data.ptr,
                msg.data.len,
                @ptrCast(&local_sa),
                @ptrCast(&peer_sa),
                @ptrCast(self),
                0, // ecn
            );
            self.unlockLsquic();

            self.processEngine();
        }
    }

    /// Run the timer-driven engine process loop.
    /// Calls lsquic_engine_process_conns() at the intervals lsquic requests
    /// via lsquic_engine_earliest_adv_tick(). Also retries unsent packets.
    /// This should be spawned via Group.async alongside runReceiveLoop.
    pub fn runTimerLoop(self: *QuicEngine, io: Io) void {
        log.debug("runTimerLoop started", .{});
        while (self.running) {
            var diff: c_int = 0;
            self.lockLsquic();
            const advisory_diff = if (lsquic.lsquic_engine_earliest_adv_tick(self.engine, &diff) != 0) diff else null;
            const has_unsent = self.has_unsent;
            self.unlockLsquic();
            const wait = computeProcessWait(advisory_diff, has_unsent);
            if (advisory_diff) |advisory| updateAdvisoryStats(&self.debug, advisory);
            switch (wait) {
                .immediate => {
                    counterInc(&self.debug.timer_immediate_count);
                    const consecutive = self.debug.current_consecutive_immediate_ticks.fetchAdd(1, .monotonic) + 1;
                    updateMax(&self.debug.max_consecutive_immediate_ticks, consecutive);
                },
                .indefinite => {
                    counterInc(&self.debug.timer_indefinite_count);
                    self.debug.current_consecutive_immediate_ticks.store(0, .monotonic);
                    self.process_wake.wait(io) catch |err| switch (err) {
                        error.Canceled => return,
                    };
                },
                .timeout_us => |us| {
                    counterInc(&self.debug.timer_timeout_count);
                    self.debug.current_consecutive_immediate_ticks.store(0, .monotonic);
                    self.process_wake.waitTimeout(io, timeoutFromMicroseconds(us)) catch |err| switch (err) {
                        error.Timeout => {},
                        error.Canceled => return,
                    };
                },
            }

            self.process_wake.reset();
            if (!self.running) return;
            self.processEngine();
        }
    }

    fn requestProcessWake(self: *QuicEngine) void {
        self.process_wake.set(self.io);
    }

    fn lockLsquic(self: *QuicEngine) void {
        self.lsquic_mutex.lockUncancelable(self.io);
    }

    fn unlockLsquic(self: *QuicEngine) void {
        self.lsquic_mutex.unlock(self.io);
    }

    /// Process lsquic connections and retry unsent packets if needed.
    fn processEngine(self: *QuicEngine) void {
        // Guard against re-entrancy: lsquic asserts that process_conns is
        // not called while already inside process_conns.
        if (self.processing.swap(true, .acq_rel)) {
            counterInc(&self.debug.process_engine_reentrant_skip_count);
            return;
        }
        const start_ns = monotonicNanoseconds();
        defer {
            if (start_ns) |start| {
                if (monotonicNanoseconds()) |end| {
                    if (end >= start) {
                        const duration_ns = end - start;
                        counterAdd(&self.debug.process_engine_total_ns, duration_ns);
                        updateMax(&self.debug.process_engine_max_ns, duration_ns);
                    }
                }
            }
            self.processing.store(false, .release);
        }
        counterInc(&self.debug.process_engine_count);
        {
            self.lockLsquic();
            defer self.unlockLsquic();
            // Retry unsent packets first (socket may now be writable)
            if (self.has_unsent) {
                self.has_unsent = false;
                counterInc(&self.debug.has_unsent_retry_count);
                lsquic.lsquic_engine_send_unsent_packets(self.engine);
            }
            lsquic.lsquic_engine_process_conns(self.engine);
        }

        // Drain pending server connection (set by onNewConn during process_conns).
        // Must happen AFTER process_conns returns to avoid re-entrancy.
        if (self.pending_server_conn) |conn| {
            self.pending_server_conn = null;
            log.debug("processEngine: pushing pending server conn to accept queue", .{});
            const queued = tryQueueOneUncancelable(ConnEvent, &self.conn_queue, self.io, .{ .conn = conn }) catch |err| {
                counterInc(&self.debug.accept_queue_closed_count);
                log.warn("processEngine: accept queue closed while handing off server conn: {}", .{err});
                conn.close(self.io);
                conn.deinit();
                return;
            };
            if (!queued) {
                counterInc(&self.debug.accept_queue_full_count);
                log.warn("processEngine: accept queue full, closing server conn", .{});
                conn.close(self.io);
                conn.deinit();
            }
        }
    }

    // ── lsquic C callbacks ─────────────────────────────────────────────

    fn onNewConn(stream_if_ctx: ?*anyopaque, lc: ?*lsquic.lsquic_conn_t) callconv(.c) ?*lsquic.lsquic_conn_ctx_t {
        log.debug("onNewConn called, stream_if_ctx={?*}, lc={?*}", .{ stream_if_ctx, lc });
        const engine: *QuicEngine = @ptrCast(@alignCast(stream_if_ctx));
        const c = lc orelse return null;

        // For client-side connections, connect() already set conn_ctx
        const existing_ctx = lsquic.lsquic_conn_get_ctx(lc);
        if (existing_ctx != null) {
            log.debug("onNewConn: client-side conn, existing ctx={?*}", .{existing_ctx});
            return @ptrCast(existing_ctx);
        }

        // Server-side: create QuicConnection wrapper and set it as the conn context.
        // For IETF QUIC servers, on_new_conn is called when the mini-conn is promoted
        // to a full connection (i.e., handshake is complete). on_hsk_done is client-only.
        const conn = QuicConnection.init(engine.allocator, c, engine) catch |err| {
            log.err("onNewConn: failed to create QuicConnection: {}", .{err});
            return null;
        };
        conn.hsk_completed = true;
        log.debug("onNewConn: server-side conn created, conn={*}", .{conn});

        // Extract peer identity stored by customVerifyCallback for this
        // concrete lsquic connection.
        if (engine.cert_verify_ctx.takeNextServerVerified()) |verified| {
            conn.peer_id = verified.peer_id;
            if (verified.host_pubkey.data) |d| conn.allocator.free(d);
            log.debug("onNewConn: server peer_id extracted from custom verify", .{});
        } else {
            log.warn("onNewConn: no verified peer info from custom verify callback", .{});
        }

        // Defer the queue handoff until after process_conns returns so we never
        // block inside lsquic callback execution.
        engine.pending_server_conn = conn;
        log.debug("onNewConn: server conn queued for accept", .{});

        return @ptrCast(conn);
    }

    fn onHskDone(lc: ?*lsquic.lsquic_conn_t, status: c_uint) callconv(.c) void {
        log.debug("onHskDone called, lc={?*}, status={}", .{ lc, status });
        if (status != lsquic.LSQ_HSK_OK and status != lsquic.LSQ_HSK_RESUMED_OK) {
            log.warn("onHskDone: handshake failed with status={}", .{status});
            // Signal failure to waitHandshake
            if (lc) |c| {
                const conn_ctx = lsquic.lsquic_conn_get_ctx(c);
                if (conn_ctx) |ctx| {
                    const conn: *QuicConnection = @ptrCast(@alignCast(ctx));
                    conn.retainRef();
                    defer conn.releaseRef();
                    const queued = tryQueueOneUncancelable(HandshakeResult, &conn.hsk_queue, conn.engine.io, .failed) catch {
                        lsquic.lsquic_conn_close(c);
                        return;
                    };
                    if (!queued) {
                        lsquic.lsquic_conn_close(c);
                    }
                }
                lsquic.lsquic_conn_close(c);
            }
            return;
        }

        const conn_ctx = lsquic.lsquic_conn_get_ctx(lc);
        if (conn_ctx) |ctx| {
            const conn: *QuicConnection = @ptrCast(@alignCast(ctx));
            conn.retainRef();
            defer conn.releaseRef();
            conn.hsk_completed = true;

            // Extract peer identity stored by customVerifyCallback for this
            // concrete lsquic connection.
            if (conn.engine.cert_verify_ctx.takeVerified(conn_ctx)) |verified| {
                conn.peer_id = verified.peer_id;
                if (verified.host_pubkey.data) |d| conn.allocator.free(d);
                log.debug("onHskDone: peer_id extracted from custom verify", .{});
            } else {
                log.warn("onHskDone: no verified peer info from custom verify callback", .{});
                const queued = tryQueueOneUncancelable(HandshakeResult, &conn.hsk_queue, conn.engine.io, .failed) catch {
                    if (lc) |c| lsquic.lsquic_conn_close(c);
                    return;
                };
                if (!queued) {
                    if (lc) |c| lsquic.lsquic_conn_close(c);
                }
                if (lc) |c| lsquic.lsquic_conn_close(c);
                return;
            }

            // Signal success to waitHandshake
            const queued = tryQueueOneUncancelable(HandshakeResult, &conn.hsk_queue, conn.engine.io, .ok) catch {
                if (lc) |c| lsquic.lsquic_conn_close(c);
                return;
            };
            if (!queued) {
                if (lc) |c| lsquic.lsquic_conn_close(c);
            }

            // Note: on_hsk_done is CLIENT-ONLY in lsquic.
            // The client already has its QuicConnection from connect(), so we
            // just update peer_id above — no need to push to conn_queue.
            log.debug("onHskDone: client handshake complete, peer_id set on existing conn", .{});
        } else {
            log.warn("onHskDone: conn_ctx is NULL (server mini-conn?)", .{});
        }
    }

    fn onConnCloseFrame(
        _: ?*lsquic.lsquic_conn_t,
        app_error: c_int,
        error_code: u64,
        reason: ?[*]const u8,
        reason_len: c_int,
    ) callconv(.c) void {
        const reason_str: []const u8 = if (reason) |r|
            r[0..@as(usize, @intCast(reason_len))]
        else
            "(none)";
        if (app_error == 0 and error_code == 0 and reason_len == 0) {
            log.debug("CONNECTION_CLOSE received: graceful close", .{});
        } else {
            log.warn("CONNECTION_CLOSE received: app_error={d}, code=0x{x}, reason=\"{s}\"", .{
                app_error, error_code, reason_str,
            });
        }
    }

    fn onConnClosed(lc: ?*lsquic.lsquic_conn_t) callconv(.c) void {
        // Log close reason from lsquic
        if (lc) |c| {
            var errbuf: [256]u8 = undefined;
            const status = lsquic.lsquic_conn_status(c, &errbuf, errbuf.len);
            const err_msg: []const u8 = blk: {
                const span = std.mem.sliceTo(&errbuf, 0);
                break :blk if (span.len > 0) span else "(none)";
            };
            switch (status) {
                lsquic.LSCONN_ST_CLOSED,
                lsquic.LSCONN_ST_GOING_AWAY,
                lsquic.LSCONN_ST_PEER_GOING_AWAY,
                lsquic.LSCONN_ST_USER_ABORTED,
                => log.debug("onConnClosed: status={d}, errmsg={s}, lc={?*}", .{
                    @as(c_int, @intCast(status)),
                    err_msg,
                    lc,
                }),
                else => log.warn("onConnClosed: status={d}, errmsg={s}, lc={?*}", .{
                    @as(c_int, @intCast(status)),
                    err_msg,
                    lc,
                }),
            }
        } else {
            log.debug("onConnClosed called, lc=null", .{});
        }
        const ctx = lsquic.lsquic_conn_get_ctx(lc);
        if (ctx) |raw| {
            const conn: *QuicConnection = @ptrCast(@alignCast(raw));
            conn.retainRef();
            defer conn.releaseRef();
            conn.closed = true;
            conn.lsquic_conn = null;
            conn.engine.cert_verify_ctx.discardVerified(ctx);
            // Clear conn context so lsquic doesn't assert on engine destroy
            if (lc) |c| lsquic.lsquic_conn_set_ctx(c, null);
            // Close both queues using engine's stored io
            conn.stream_queue.close(conn.io);
            conn.outbound_stream_queue.close(conn.io);
            conn.hsk_queue.close(conn.io);
        }
    }

    fn onNewStream(stream_if_ctx: ?*anyopaque, ls: ?*lsquic.lsquic_stream_t) callconv(.c) ?*lsquic.lsquic_stream_ctx_t {
        log.debug("onNewStream called, ls={?*}", .{ls});
        const engine: *QuicEngine = @ptrCast(@alignCast(stream_if_ctx));
        const s = ls orelse return null;
        const sid = lsquic.lsquic_stream_id(s);
        const is_server_stream = (sid % 4 == 1);
        const is_local = (engine.is_server == is_server_stream);
        log.info("onNewStream: id={d} local={} (engine.is_server={}, stream_server_init={})", .{
            sid, is_local, engine.is_server, is_server_stream,
        });

        // Find the connection this stream belongs to
        const lc = lsquic.lsquic_stream_conn(s);
        const conn_ctx = lsquic.lsquic_conn_get_ctx(lc);
        if (conn_ctx == null) return null;

        const conn: *QuicConnection = @ptrCast(@alignCast(conn_ctx));
        conn.retainRef();
        defer conn.releaseRef();

        // Create stream wrapper
        const stream = QuicStream.init(engine.allocator, s, conn) catch return null;
        stream.markQueued();

        // Route stream to the correct queue based on QUIC stream ID parity.
        // RFC 9000: client-initiated bidi = 4n+0, server-initiated bidi = 4n+1.
        // Locally-initiated streams go to outbound_stream_queue (for openStream),
        // remotely-initiated streams go to stream_queue (for acceptStream).
        const stream_id = lsquic.lsquic_stream_id(s);
        const is_server_initiated = (stream_id % 4 == 1);
        const is_locally_initiated = (engine.is_server == is_server_initiated);

        if (is_locally_initiated) {
            const queued = tryQueueOneUncancelable(StreamEvent, &conn.outbound_stream_queue, engine.io, .{ .stream = stream }) catch |err| {
                log.warn("onNewStream: outbound stream queue closed: {}", .{err});
                stream.destroyRejectedNoLock();
                return null;
            };
            if (!queued) {
                log.warn("onNewStream: dropping local stream because outbound stream queue is full", .{});
                stream.destroyRejectedNoLock();
                return null;
            }
        } else {
            // Do not arm wantread until the application asks to read.
            // QuicStream.read() arms lsquic_stream_wantread lazily; arming here
            // can create repeated zero-byte callbacks before STREAM payload has
            // been decoded, which in production showed up as an immediate timer
            // hot loop.
            if (armReadOnNewStream(is_locally_initiated)) {
                _ = lsquic.lsquic_stream_wantread(s, 1);
            }
            const queued = tryQueueOneUncancelable(StreamEvent, &conn.stream_queue, engine.io, .{ .stream = stream }) catch |err| {
                counterInc(&engine.debug.accept_queue_closed_count);
                log.warn("onNewStream: inbound stream queue closed: {}", .{err});
                stream.destroyRejectedNoLock();
                return null;
            };
            if (!queued) {
                counterInc(&engine.debug.accept_queue_full_count);
                log.warn("onNewStream: dropping inbound stream because accept queue is full", .{});
                stream.destroyRejectedNoLock();
                return null;
            }
        }

        return @ptrCast(stream);
    }

    fn onRead(ls: ?*lsquic.lsquic_stream_t, _: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
        const s = ls orelse return;
        const raw = lsquic.lsquic_stream_get_ctx(s) orelse return;
        const stream: *QuicStream = @ptrCast(@alignCast(raw));
        stream.retainRef();
        defer stream.releaseRef();

        const stream_id = lsquic.lsquic_stream_id(s);
        counterInc(&stream.conn.engine.debug.on_read_count);
        var buf: [4096]u8 = undefined;
        const n = lsquic.lsquic_stream_read(s, &buf, buf.len);
        if (n < 0) {
            counterInc(&stream.conn.engine.debug.on_read_would_block_count);
            // No bytes are currently available. Drop wantread until the
            // consumer calls read() again so we do not spin callbacks.
            _ = lsquic.lsquic_stream_wantread(s, 0);
            log.debug("onRead: stream {d} EWOULDBLOCK (n={d})", .{ stream_id, n });
            return;
        }
        if (n == 0) {
            if (!stream.has_received_data) {
                counterInc(&stream.conn.engine.debug.on_read_zero_before_data_count);
                stream.spurious_read_count += 1;
                switch (zeroBeforeDataAction(stream.spurious_read_count)) {
                    .retry => {
                        if (stream.spurious_read_count <= 3) {
                            log.debug("onRead: stream {d} no data yet (tick {d})", .{ stream_id, stream.spurious_read_count });
                        }
                    },
                    .defensive_close => {
                        log.warn("onRead: stream {d} repeated zero-byte reads before payload (count={d}); disarming and closing stream", .{
                            stream_id,
                            stream.spurious_read_count,
                        });
                        _ = lsquic.lsquic_stream_wantread(s, 0);
                        stream.closeNoLock();
                        stream.read_queue.close(stream.io);
                        stream.write_queue.close(stream.io);
                    },
                }
                return;
            }
            // Genuine EOF — peer sent FIN after sending data.
            counterInc(&stream.conn.engine.debug.on_read_eof_count);
            log.debug("onRead: stream {d} EOF", .{stream_id});
            _ = lsquic.lsquic_stream_wantread(s, 0);
            stream.read_queue.close(stream.io);
            return;
        }

        const len: usize = @intCast(n);
        counterAdd(&stream.conn.engine.debug.on_read_bytes, len);
        log.debug("onRead: stream {d} got {d} bytes", .{ stream_id, len });
        stream.has_received_data = true;
        stream.spurious_read_count = 0;
        // Allocate owned copy of the data
        const owned = stream.allocator.alloc(u8, len) catch {
            stream.read_queue.close(stream.io);
            return;
        };
        @memcpy(owned, buf[0..len]);

        // Push read event
        const queued = tryQueueOneUncancelable(ReadEvent, &stream.read_queue, stream.io, .{
            .data = owned,
            .owned_buf = owned,
        }) catch {
            counterInc(&stream.conn.engine.debug.read_queue_closed_count);
            stream.allocator.free(owned);
            log.warn("onRead: read queue closed, closing stream", .{});
            stream.closeNoLock();
            stream.read_queue.close(stream.io);
            stream.write_queue.close(stream.io);
            return;
        };
        if (!queued) {
            counterInc(&stream.conn.engine.debug.read_queue_full_count);
            stream.allocator.free(owned);
            log.warn("onRead: read queue full, closing stream", .{});
            stream.closeNoLock();
            stream.read_queue.close(stream.io);
            stream.write_queue.close(stream.io);
        }
    }

    fn onWrite(ls: ?*lsquic.lsquic_stream_t, _: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
        if (ls) |s| {
            const raw = lsquic.lsquic_stream_get_ctx(s) orelse return;
            const stream: *QuicStream = @ptrCast(@alignCast(raw));
            stream.retainRef();
            defer stream.releaseRef();
            stream.signalWriteReady();
            _ = lsquic.lsquic_stream_wantwrite(s, 0);
        }
    }

    fn onStreamClose(ls: ?*lsquic.lsquic_stream_t, _: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
        const s = ls orelse return;
        const raw = lsquic.lsquic_stream_get_ctx(s) orelse return;
        const stream: *QuicStream = @ptrCast(@alignCast(raw));
        stream.retainRef();
        defer stream.releaseRef();
        lsquic.lsquic_stream_set_ctx(s, null);
        log.debug("onStreamClose called", .{});

        // Drain any remaining data before closing. lsquic may call
        // onClose before delivering all buffered data via onRead.
        var drain_buf: [4096]u8 = undefined;
        var drain_total: usize = 0;
        while (true) {
            const n = lsquic.lsquic_stream_read(s, &drain_buf, drain_buf.len);
            if (n <= 0) break;
            const len: usize = @intCast(n);
            drain_total += len;
            // Push drained data to the read queue
            const owned = stream.allocator.alloc(u8, len) catch break;
            @memcpy(owned, drain_buf[0..len]);
            const queued = tryQueueOneUncancelable(ReadEvent, &stream.read_queue, stream.io, .{
                .data = owned,
                .owned_buf = owned,
            }) catch {
                stream.allocator.free(owned);
                break;
            };
            if (!queued) {
                stream.allocator.free(owned);
                break;
            }
        }
        if (drain_total > 0) {
            log.info("onStreamClose: drained {d} bytes from stream", .{drain_total});
        }

        stream.lsquic_stream = null;
        stream.beginShutdown();
        stream.releaseRef();
        // Don't destroy stream here — the reader (swarmStreamTask /
        // multistream negotiation) may still be using it. The stream
        // will be cleaned up when the reader finishes and the QuicStream
        // goes out of scope or is explicitly closed.
    }

    fn packetsOut(
        packets_out_ctx: ?*anyopaque,
        specs: [*c]const lsquic.lsquic_out_spec,
        count: c_uint,
    ) callconv(.c) c_int {
        log.debug("packetsOut called, count={}", .{count});
        const engine: *QuicEngine = @ptrCast(@alignCast(packets_out_ctx));
        counterInc(&engine.debug.packets_out_call_count);

        var sent: c_int = 0;
        var i: c_uint = 0;
        while (i < count) : (i += 1) {
            const spec = specs[i];
            // Build msghdr from spec
            var msg: std.c.msghdr_const = std.mem.zeroes(std.c.msghdr_const);
            msg.iov = @ptrCast(spec.iov);
            msg.iovlen = @intCast(spec.iovlen);
            const sa: ?*const std.c.sockaddr = @ptrCast(@alignCast(spec.dest_sa));
            msg.name = sa;
            msg.namelen = if (sa) |s| switch (s.family) {
                std.posix.AF.INET => @sizeOf(std.c.sockaddr.in),
                std.posix.AF.INET6 => @sizeOf(std.c.sockaddr.in6),
                else => 0,
            } else 0;

            const local_sa: ?*const std.c.sockaddr = @ptrCast(@alignCast(spec.local_sa));
            const local_addr = if (local_sa) |lsa|
                sockaddrToIpAddress(lsa) orelse return -1
            else
                return -1;
            const sock = engine.findSocketForLocalAddr(local_addr) orelse return -1;

            const rc = std.c.sendmsg(sock.handle, &msg, 0);
            if (rc < 0) {
                const e: std.c.E = @enumFromInt(std.c._errno().*);
                if (e == .AGAIN or e == .INTR) {
                    counterInc(&engine.debug.packets_out_eagain_count);
                    // Non-blocking socket would block or interrupted.
                    // Flag unsent packets so the timer loop can retry
                    // via lsquic_engine_send_unsent_packets().
                    engine.has_unsent = true;
                    engine.requestProcessWake();
                    return sent;
                }
                counterInc(&engine.debug.packets_out_error_count);
                return -1;
            }
            counterInc(&engine.debug.packets_out_sent_count);
            sent += 1;
        }
        return sent;
    }

    fn findSocketForLocalAddr(self: *const QuicEngine, addr: net.IpAddress) ?net.Socket {
        for (self.sockets.items, self.bound_addrs.items) |sock, bound_addr| {
            if (ipAddressEql(bound_addr, addr)) return sock;
        }
        for (self.sockets.items, self.bound_addrs.items) |sock, bound_addr| {
            if (sameFamilyAndPort(bound_addr, addr)) return sock;
        }
        return null;
    }

    fn getSslCtx(peer_ctx: ?*anyopaque, _: ?*const lsquic.struct_sockaddr) callconv(.c) ?*lsquic.struct_ssl_ctx_st {
        log.debug("getSslCtx called", .{});
        const engine: *QuicEngine = @ptrCast(@alignCast(peer_ctx));
        return @ptrCast(engine.ssl_ctx);
    }

    /// BoringSSL custom verify callback registered via SSL_CTX_set_custom_verify.
    /// Retrieves CertVerifyCtx from SSL_CTX ex_data (no threadlocal needed).
    /// Called for both client and server sides since getSslCtx is called for both.
    fn customVerifyCallback(
        ssl_obj: ?*ssl.SSL,
        out_alert: [*c]u8,
    ) callconv(.c) ssl.enum_ssl_verify_result_t {
        const s = ssl_obj orelse return ssl.ssl_verify_invalid;

        // Get the SSL_CTX from the SSL object
        const ssl_ctx: *ssl.SSL_CTX = ssl.SSL_get_SSL_CTX(s) orelse {
            log.warn("customVerifyCallback: SSL_get_SSL_CTX returned null", .{});
            return ssl.ssl_verify_invalid;
        };

        // Retrieve the CertVerifyCtx from SSL_CTX ex_data
        const raw_ptr = ssl.SSL_CTX_get_ex_data(@ptrCast(ssl_ctx), g_ssl_ctx_ex_idx) orelse {
            log.warn("customVerifyCallback: SSL_CTX_get_ex_data returned null (idx={})", .{g_ssl_ctx_ex_idx});
            return ssl.ssl_verify_invalid;
        };
        const ctx: *CertVerifyCtx = @ptrCast(@alignCast(raw_ptr));
        const lsquic_ssl: *const lsquic.struct_ssl_st = @ptrCast(s);
        const lc = lsquic.lsquic_ssl_to_conn(lsquic_ssl) orelse {
            log.warn("customVerifyCallback: lsquic_ssl_to_conn returned null", .{});
            if (out_alert) |a| a.* = ssl.SSL_AD_INTERNAL_ERROR;
            return ssl.ssl_verify_invalid;
        };

        // Get the peer certificate from the SSL connection
        const cert: *ssl.X509 = ssl.SSL_get_peer_certificate(s) orelse {
            log.warn("customVerifyCallback: no peer certificate — Lighthouse may not be sending a cert (mutual TLS not requested?)", .{});
            // Signal bad certificate alert
            if (out_alert) |a| a.* = ssl.SSL_AD_CERTIFICATE_UNKNOWN;
            return ssl.ssl_verify_invalid;
        };
        defer ssl.X509_free(cert);

        log.debug("customVerifyCallback: verifying peer certificate", .{});

        // Verify the libp2p certificate extension and extract peer identity
        const info = tls.verifyAndExtractPeerInfo(ctx.allocator, cert) catch |err| {
            log.warn("customVerifyCallback: verifyAndExtractPeerInfo failed: {s}", .{@errorName(err)});
            if (out_alert) |a| a.* = ssl.SSL_AD_BAD_CERTIFICATE;
            return ssl.ssl_verify_invalid;
        };

        if (!info.is_valid) {
            log.warn("customVerifyCallback: cert signature verification failed (extension sig mismatch)", .{});
            if (info.host_pubkey.data) |d| ctx.allocator.free(d);
            if (out_alert) |a| a.* = ssl.SSL_AD_BAD_CERTIFICATE;
            return ssl.ssl_verify_invalid;
        }

        log.debug("customVerifyCallback: peer verified, key_type={}, peer_id_bytes={d}", .{
            info.host_pubkey.type, if (info.host_pubkey.data) |d| d.len else 0,
        });

        const conn_ctx = lsquic.lsquic_conn_get_ctx(lc);

        // Store verified peer info for consumption by onNewConn/onHskDone.
        // For clients, key by the stable conn_ctx pointer rather than the
        // lsquic connection pointer, which may differ across handshake stages.
        ctx.storeVerified(conn_ctx, ssl.SSL_is_server(s) == 1, .{
            .peer_id = info.peer_id,
            .host_pubkey = info.host_pubkey,
        }) catch |err| {
            log.warn("customVerifyCallback: failed to store verified peer info: {s}", .{@errorName(err)});
            if (info.host_pubkey.data) |d| ctx.allocator.free(d);
            if (out_alert) |a| a.* = ssl.SSL_AD_INTERNAL_ERROR;
            return ssl.ssl_verify_invalid;
        };

        log.debug("customVerifyCallback: peer verified successfully", .{});
        return ssl.ssl_verify_ok;
    }
};

// ── Helpers ────────────────────────────────────────────────────────────

/// Convert std.Io.net.IpAddress to a C sockaddr for lsquic interop.
/// Returns a sockaddr_storage-sized union that can be cast to sockaddr*.
const SockaddrStorage = extern struct {
    // Big enough for both sockaddr_in (16 bytes) and sockaddr_in6 (28 bytes).
    // Aligned to 4 to safely cast to *sockaddr (alignment 2 on Linux, 4 on macOS).
    data: [128]u8 align(4) = std.mem.zeroes([128]u8),
};

pub fn ipAddressToSockaddr(addr: net.IpAddress) SockaddrStorage {
    var storage = SockaddrStorage{};
    switch (addr) {
        .ip4 => |a| {
            if (builtin.os.tag.isDarwin()) {
                // macOS sockaddr_in: len(1) + family(1) + port(2) + addr(4) + zero(8)
                storage.data[0] = @sizeOf(std.c.sockaddr.in);
                storage.data[1] = @intCast(std.posix.AF.INET);
            } else {
                // Linux sockaddr_in: family(2) + port(2) + addr(4) + zero(8)
                const family: u16 = @intCast(std.posix.AF.INET);
                @memcpy(storage.data[0..2], std.mem.asBytes(&family));
            }
            const port_be = std.mem.nativeToBig(u16, a.port);
            const offset: usize = if (builtin.os.tag.isDarwin()) 2 else 2;
            @memcpy(storage.data[offset..][0..2], std.mem.asBytes(&port_be));
            @memcpy(storage.data[offset + 2 ..][0..4], &a.bytes);
        },
        .ip6 => |a| {
            if (builtin.os.tag.isDarwin()) {
                storage.data[0] = @sizeOf(std.c.sockaddr.in6);
                storage.data[1] = @intCast(std.posix.AF.INET6);
            } else {
                const family: u16 = @intCast(std.posix.AF.INET6);
                @memcpy(storage.data[0..2], std.mem.asBytes(&family));
            }
            const port_be = std.mem.nativeToBig(u16, a.port);
            const offset: usize = if (builtin.os.tag.isDarwin()) 2 else 2;
            @memcpy(storage.data[offset..][0..2], std.mem.asBytes(&port_be));
            // flowinfo at offset+4 (4 bytes, zeroed)
            // addr at offset+8 (16 bytes)
            @memcpy(storage.data[offset + 6 ..][0..16], &a.bytes);
        },
    }
    return storage;
}

fn sockaddrToIpAddress(addr: *const std.c.sockaddr) ?net.IpAddress {
    return switch (addr.family) {
        std.posix.AF.INET => blk: {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
            break :blk .{
                .ip4 = .{
                    .port = std.mem.bigToNative(u16, in.port),
                    .bytes = @bitCast(in.addr),
                },
            };
        },
        std.posix.AF.INET6 => blk: {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            break :blk .{
                .ip6 = .{
                    .port = std.mem.bigToNative(u16, in6.port),
                    .bytes = in6.addr,
                    .flow = in6.flowinfo,
                    .interface = .{ .index = in6.scope_id },
                },
            };
        },
        else => null,
    };
}

fn ipAddressEql(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| a4.port == b4.port and std.mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| {
                return a6.port == b6.port and
                    a6.flow == b6.flow and
                    a6.interface.index == b6.interface.index and
                    std.mem.eql(u8, &a6.bytes, &b6.bytes);
            },
        },
    };
}

fn sameFamilyAndPort(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| a4.port == b4.port,
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| a6.port == b6.port,
        },
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

test "zero-before-data read policy retries briefly then defensively closes" {
    try std.testing.expectEqual(ZeroBeforeDataAction.retry, zeroBeforeDataAction(0));
    try std.testing.expectEqual(ZeroBeforeDataAction.retry, zeroBeforeDataAction(zero_before_data_read_close_threshold - 1));
    try std.testing.expectEqual(ZeroBeforeDataAction.defensive_close, zeroBeforeDataAction(zero_before_data_read_close_threshold));
}

test "new QUIC streams do not arm read callbacks before application read" {
    try std.testing.expect(!armReadOnNewStream(true));
    try std.testing.expect(!armReadOnNewStream(false));
}

test "CertVerifyCtx stores and retrieves by connection context" {
    const allocator = std.testing.allocator;
    var ctx = CertVerifyCtx.init(allocator);
    defer ctx.deinit();
    const conn_ctx_a: *anyopaque = @ptrFromInt(0x1000);

    // Create a test VerifiedPeer with dummy data
    const test_key_data = try allocator.dupe(u8, &[_]u8{ 1, 2, 3, 4 });
    const test_peer = CertVerifyCtx.VerifiedPeer{
        .peer_id = std.mem.zeroes(PeerId),
        .host_pubkey = keys.PublicKey{ .type = .ED25519, .data = test_key_data },
    };

    try ctx.storeVerified(conn_ctx_a, false, test_peer);
    const peer = ctx.takeVerified(conn_ctx_a);
    try std.testing.expect(peer != null);
    // Caller owns the taken peer's host_pubkey data
    allocator.free(peer.?.host_pubkey.data.?);
}

test "CertVerifyCtx returns null when empty" {
    const allocator = std.testing.allocator;
    var ctx = CertVerifyCtx.init(allocator);
    defer ctx.deinit();
    const conn_ctx_a: *anyopaque = @ptrFromInt(0x1000);

    const peer = ctx.takeVerified(conn_ctx_a);
    try std.testing.expect(peer == null);
}

test "CertVerifyCtx keeps peer identities isolated per connection context" {
    const allocator = std.testing.allocator;
    var ctx = CertVerifyCtx.init(allocator);
    defer ctx.deinit();
    const conn_ctx_a: *anyopaque = @ptrFromInt(0x1000);
    const conn_ctx_b: *anyopaque = @ptrFromInt(0x2000);

    try ctx.storeVerified(conn_ctx_a, false, .{
        .peer_id = std.mem.zeroes(PeerId),
        .host_pubkey = .{
            .type = .ED25519,
            .data = try allocator.dupe(u8, &[_]u8{1}),
        },
    });
    try ctx.storeVerified(conn_ctx_b, false, .{
        .peer_id = std.mem.zeroes(PeerId),
        .host_pubkey = .{
            .type = .ED25519,
            .data = try allocator.dupe(u8, &[_]u8{2}),
        },
    });

    const peer_b = ctx.takeVerified(conn_ctx_b) orelse return error.TestUnexpectedNull;
    defer allocator.free(peer_b.host_pubkey.data.?);
    try std.testing.expectEqual(@as(usize, 1), peer_b.host_pubkey.data.?.len);
    try std.testing.expectEqual(@as(u8, 2), peer_b.host_pubkey.data.?[0]);

    const peer_a = ctx.takeVerified(conn_ctx_a) orelse return error.TestUnexpectedNull;
    defer allocator.free(peer_a.host_pubkey.data.?);
    try std.testing.expectEqual(@as(usize, 1), peer_a.host_pubkey.data.?.len);
    try std.testing.expectEqual(@as(u8, 1), peer_a.host_pubkey.data.?[0]);
}

test "CertVerifyCtx preserves server-side verification order" {
    const allocator = std.testing.allocator;
    var ctx = CertVerifyCtx.init(allocator);
    defer ctx.deinit();
    const conn_a: *lsquic.lsquic_conn_t = @ptrFromInt(0x1000);
    const conn_b: *lsquic.lsquic_conn_t = @ptrFromInt(0x2000);

    try ctx.storeVerified(conn_a, true, .{
        .peer_id = std.mem.zeroes(PeerId),
        .host_pubkey = .{
            .type = .ED25519,
            .data = try allocator.dupe(u8, &[_]u8{1}),
        },
    });
    try ctx.storeVerified(conn_b, true, .{
        .peer_id = std.mem.zeroes(PeerId),
        .host_pubkey = .{
            .type = .ED25519,
            .data = try allocator.dupe(u8, &[_]u8{2}),
        },
    });

    const peer_a = ctx.takeNextServerVerified() orelse return error.TestUnexpectedNull;
    defer allocator.free(peer_a.host_pubkey.data.?);
    try std.testing.expectEqual(@as(u8, 1), peer_a.host_pubkey.data.?[0]);

    const peer_b = ctx.takeNextServerVerified() orelse return error.TestUnexpectedNull;
    defer allocator.free(peer_b.host_pubkey.data.?);
    try std.testing.expectEqual(@as(u8, 2), peer_b.host_pubkey.data.?[0]);
}

test "tryQueueOneUncancelable reports full queues without blocking" {
    const io = std.testing.io;
    var buf: [1]u8 = undefined;
    var queue = Io.Queue(u8).init(&buf);

    try std.testing.expect(try tryQueueOneUncancelable(u8, &queue, io, 1));
    try std.testing.expect(!(try tryQueueOneUncancelable(u8, &queue, io, 2)));
    try std.testing.expectEqual(@as(u8, 1), try queue.getOne(io));
}

test "receiveLoopBackoffMs grows exponentially and caps" {
    try std.testing.expectEqual(@as(u64, 0), receiveLoopBackoffMs(0));
    try std.testing.expectEqual(@as(u64, 1), receiveLoopBackoffMs(1));
    try std.testing.expectEqual(@as(u64, 2), receiveLoopBackoffMs(2));
    try std.testing.expectEqual(@as(u64, 4), receiveLoopBackoffMs(3));
    try std.testing.expectEqual(@as(u64, 64), receiveLoopBackoffMs(7));
    try std.testing.expectEqual(@as(u64, 100), receiveLoopBackoffMs(8));
}

test "isTerminalReceiveError only treats broken local socket as terminal" {
    try std.testing.expect(isTerminalReceiveError(error.SocketUnconnected));
    try std.testing.expect(!isTerminalReceiveError(error.ConnectionResetByPeer));
    try std.testing.expect(!isTerminalReceiveError(error.NetworkDown));
    try std.testing.expect(!isTerminalReceiveError(error.SystemResources));
}

test "computeProcessWait prefers explicit wake, advisory tick, and unsent retry appropriately" {
    try std.testing.expectEqual(ProcessWait.immediate, computeProcessWait(0, false));
    try std.testing.expectEqual(ProcessWait.immediate, computeProcessWait(-5, true));
    try std.testing.expectEqual(ProcessWait.indefinite, computeProcessWait(null, false));

    switch (computeProcessWait(25_000, false)) {
        .timeout_us => |us| try std.testing.expectEqual(@as(i64, 25_000), us),
        else => return error.TestUnexpectedResult,
    }

    switch (computeProcessWait(null, true)) {
        .timeout_us => |us| try std.testing.expectEqual(unsent_retry_interval_ms * std.time.us_per_ms, us),
        else => return error.TestUnexpectedResult,
    }

    switch (computeProcessWait(25_000, true)) {
        .timeout_us => |us| try std.testing.expectEqual(@as(i64, 10_000), us),
        else => return error.TestUnexpectedResult,
    }

    switch (computeProcessWait(5_000, true)) {
        .timeout_us => |us| try std.testing.expectEqual(@as(i64, 5_000), us),
        else => return error.TestUnexpectedResult,
    }
}

test "QuicEngine init and deinit" {
    const allocator = std.testing.allocator;
    const engine = QuicEngine.init(allocator, std.testing.io, .{}) catch |err| {
        // If lsquic init fails (e.g., missing SSL setup), skip
        std.log.warn("QuicEngine init failed (expected in unit test): {}", .{err});
        return;
    };
    defer engine.deinit();

    try std.testing.expect(!engine.is_server);
    try std.testing.expect(!engine.running);
}

test "ipAddressToSockaddr converts IPv4 correctly" {
    const addr = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 42 }, .port = 8080 } };
    const storage = ipAddressToSockaddr(addr);

    if (builtin.os.tag.isDarwin()) {
        // macOS: sin_len(1) + sin_family(1) + sin_port(2) + sin_addr(4)
        try std.testing.expectEqual(@as(u8, @sizeOf(std.c.sockaddr.in)), storage.data[0]);
        try std.testing.expectEqual(@as(u8, @intCast(std.posix.AF.INET)), storage.data[1]);
    } else {
        // Linux: sin_family(2, little-endian) + sin_port(2) + sin_addr(4)
        const family = std.mem.readInt(u16, storage.data[0..2], .little);
        try std.testing.expectEqual(@as(u16, @intCast(std.posix.AF.INET)), family);
    }

    // Port is always at offset 2, big-endian
    const port_be = std.mem.readInt(u16, storage.data[2..4], .big);
    try std.testing.expectEqual(@as(u16, 8080), port_be);

    // IPv4 addr at offset 4
    try std.testing.expectEqual(@as(u8, 192), storage.data[4]);
    try std.testing.expectEqual(@as(u8, 168), storage.data[5]);
    try std.testing.expectEqual(@as(u8, 1), storage.data[6]);
    try std.testing.expectEqual(@as(u8, 42), storage.data[7]);
}

test "ipAddressToSockaddr converts IPv6 correctly" {
    const addr = net.IpAddress{ .ip6 = .{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 },
        .port = 443,
    } };
    const storage = ipAddressToSockaddr(addr);

    if (builtin.os.tag.isDarwin()) {
        try std.testing.expectEqual(@as(u8, @sizeOf(std.c.sockaddr.in6)), storage.data[0]);
        try std.testing.expectEqual(@as(u8, @intCast(std.posix.AF.INET6)), storage.data[1]);
    } else {
        const family = std.mem.readInt(u16, storage.data[0..2], .little);
        try std.testing.expectEqual(@as(u16, @intCast(std.posix.AF.INET6)), family);
    }

    const port_be = std.mem.readInt(u16, storage.data[2..4], .big);
    try std.testing.expectEqual(@as(u16, 443), port_be);
    try std.testing.expectEqual(@as(u8, 0x20), storage.data[8]);
    try std.testing.expectEqual(@as(u8, 0x01), storage.data[9]);
    try std.testing.expectEqual(@as(u8, 0x0d), storage.data[10]);
    try std.testing.expectEqual(@as(u8, 0xb8), storage.data[11]);
    try std.testing.expectEqual(@as(u8, 0x01), storage.data[23]);
}
