const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const router_mod = @import("router.zig");
const codec_mod = @import("codec.zig");
const config_mod = @import("config.zig");
const transport_mod = @import("../../transport/transport.zig");
const rpc = @import("../../proto/rpc.proto.zig");
const AnyStream = transport_mod.AnyStream;

const Config = config_mod.Config;
const Event = config_mod.Event;
const ValidationResult = config_mod.ValidationResult;
const FrameDecoder = codec_mod.FrameDecoder;

const log = std.log.scoped(.gossipsub_service);

/// GossipSub Service — wraps the comptime-generic Router and satisfies
/// both the Switch protocol Handler interface and the Router's Handler interface.
///
/// The Service uses a pending-sends queue for outbound RPCs: when the Router
/// calls `sendRpc`, the data is enqueued. The integration layer (or test harness)
/// drains the queue via `drainPendingSends` and writes to actual streams.
///
/// ## Usage
///
/// ```zig
/// const svc = try Service.init(allocator, .{
///     .signature_policy = .strict_no_sign,
///     .publish_policy = .anonymous,
///     .msg_id_fn = myNoSignMsgId,
/// });
/// defer svc.deinit(io);
///
/// try svc.subscribe(io, "my-topic");
/// _ = try svc.publish(io, "my-topic", "hello world");
///
/// // Drain pending sends and write to peer streams
/// const sends = svc.drainPendingSends(io);
/// for (sends) |s| {
///     // write s.data to s.peer's outbound stream...
///     allocator.free(s.peer);
///     allocator.free(s.data);
/// }
/// allocator.free(sends);
/// ```
pub const Service = struct {
    const Self = @This();
    const RouterType = router_mod.Router(Self);

    allocator: Allocator,
    router: RouterType,
    /// Pending outbound RPC data per peer.
    /// Populated by the Router via sendRpc; drained by the integration layer.
    pending_sends: std.ArrayList(PendingRpc),
    pending_send_bytes: usize,
    /// PRNG state for randomU64 (xorshift64).
    rng_state: u64,
    /// Current time in milliseconds, set externally via setTime.
    time_ms: u64,
    /// Outbound streams keyed by peer ID (owned keys).
    outbound_streams: std.StringHashMap(*InstalledPeerStream),
    /// Topics we are subscribed to (owned keys), for announcing to new peers.
    tracked_subscriptions: std.StringHashMap(void),
    /// Serializes router and stream state across concurrent service fibers.
    state_mu: Io.Mutex,

    /// An AnyStream with heap-allocated backing that can be freed.
    const OwnedStream = struct {
        stream: AnyStream,
        /// Raw pointer to the heap-allocated stream backing.
        backing_ptr: *anyopaque,
        /// Destructor that frees the backing_ptr via the allocator.
        destroy_fn: *const fn (alloc: Allocator, ptr: *anyopaque) void,

        fn close(self: OwnedStream, io: Io) void {
            self.stream.close(io);
        }

        fn write(self: OwnedStream, io: Io, data: []const u8) anyerror!usize {
            return self.stream.write(io, data);
        }

        fn destroyBacking(self: OwnedStream, alloc: Allocator) void {
            self.destroy_fn(alloc, self.backing_ptr);
        }
    };

    const InstalledPeerStream = struct {
        owned: OwnedStream,
        ref_count: std.atomic.Value(usize) = .init(1),

        fn retain(self: *InstalledPeerStream) void {
            _ = self.ref_count.fetchAdd(1, .monotonic);
        }

        fn release(self: *InstalledPeerStream, alloc: Allocator) void {
            var current = self.ref_count.load(.acquire);
            while (true) {
                if (current == 0) {
                    log.err("gossipsub managed stream release underflow", .{});
                    return;
                }
                if (self.ref_count.cmpxchgWeak(current, current - 1, .acq_rel, .acquire)) |observed| {
                    current = observed;
                    continue;
                }
                if (current == 1) {
                    self.owned.destroyBacking(alloc);
                    alloc.destroy(self);
                }
                return;
            }
        }

        fn close(self: *InstalledPeerStream, io: Io) void {
            self.owned.close(io);
        }

        fn write(self: *InstalledPeerStream, io: Io, data: []const u8) anyerror!usize {
            return self.owned.write(io, data);
        }
    };

    fn installPeerStream(self: *Self, peer_id: []const u8, stream: anytype) !?*InstalledPeerStream {
        if (self.outbound_streams.contains(peer_id)) return null;

        const StreamT = @TypeOf(stream.*);
        if (!@hasDecl(StreamT, "detachOwnedStream")) {
            @compileError("gossipsub peer streams must support detachOwnedStream()");
        }

        const detached_stream = stream.detachOwnedStream();
        const DetachedStreamT = @TypeOf(detached_stream);
        const heap_stream = try self.allocator.create(DetachedStreamT);
        errdefer self.allocator.destroy(heap_stream);

        heap_stream.* = detached_stream;

        const installed = try self.allocator.create(InstalledPeerStream);
        errdefer self.allocator.destroy(installed);

        installed.* = .{
            .owned = .{
                .stream = AnyStream.wrap(DetachedStreamT, heap_stream),
                .backing_ptr = @ptrCast(heap_stream),
                .destroy_fn = struct {
                    fn destroy(alloc: Allocator, ptr: *anyopaque) void {
                        const p: *DetachedStreamT = @ptrCast(@alignCast(ptr));
                        if (@hasDecl(DetachedStreamT, "deinit")) {
                            p.deinit();
                        }
                        alloc.destroy(p);
                    }
                }.destroy,
            },
        };
        errdefer installed.owned.destroyBacking(self.allocator);

        const peer_copy = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(peer_copy);

        try self.outbound_streams.put(peer_copy, installed);
        return installed;
    }

    /// A pending outbound RPC message to a specific peer.
    pub const PendingRpc = struct {
        /// Peer identifier (owned copy).
        peer: []const u8,
        /// Encoded RPC data (owned copy).
        data: []const u8,
    };

    /// Protocol identifier for Switch integration.
    pub const id = config_mod.protocol_ids.v1_2;

    /// Create a new heap-allocated Service.
    ///
    /// The Service is heap-allocated because it contains a self-referential
    /// pointer: Router stores `*Handler` which points back to the Service.
    pub fn init(allocator: Allocator, gs_config: Config) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .router = undefined,
            .pending_sends = .empty,
            .pending_send_bytes = 0,
            .rng_state = 12345,
            .time_ms = 0,
            .outbound_streams = std.StringHashMap(*InstalledPeerStream).init(allocator),
            .tracked_subscriptions = std.StringHashMap(void).init(allocator),
            .state_mu = .init,
        };
        self.router = RouterType.init(allocator, gs_config, self) catch |e| {
            allocator.destroy(self);
            return e;
        };
        return self;
    }

    fn lock(self: *Self, io: Io) void {
        self.state_mu.lockUncancelable(io);
    }

    fn unlock(self: *Self, io: Io) void {
        self.state_mu.unlock(io);
    }

    /// Release all resources owned by this Service.
    pub fn deinit(self: *Self, io: Io) void {
        for (self.pending_sends.items) |p| {
            self.allocator.free(p.peer);
            self.allocator.free(p.data);
        }
        self.pending_sends.deinit(self.allocator);

        // Clean up outbound streams
        var os_iter = self.outbound_streams.iterator();
        while (os_iter.next()) |entry| {
            entry.value_ptr.*.close(io);
            entry.value_ptr.*.release(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.outbound_streams.deinit();

        // Clean up tracked subscriptions
        var ts_iter = self.tracked_subscriptions.iterator();
        while (ts_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.tracked_subscriptions.deinit();

        self.router.deinit();
        self.allocator.destroy(self);
    }

    // ---------------------------------------------------------------
    // Switch Protocol Handler interface
    // ---------------------------------------------------------------

    /// Handle an inbound gossipsub stream from a remote peer.
    /// Reads varint-length-prefixed protobuf frames from the stream using
    /// FrameDecoder and passes each decoded RPC to the Router.
    /// Pure reader — peer lifecycle is managed by the Switch via
    /// onPeerDisconnected (rust-libp2p pattern).
    pub fn handleInbound(self: *Self, io: Io, stream: anytype, ctx: anytype) !void {
        const peer_id: []const u8 = if (@hasField(@TypeOf(ctx), "peer_id"))
            (ctx.peer_id orelse return)
        else
            return;

        var installed_stream: ?*InstalledPeerStream = null;
        defer if (installed_stream) |installed| installed.release(self.allocator);

        {
            self.lock(io);
            defer self.unlock(io);

            self.router.addPeer(peer_id) catch {};
            if (try self.installPeerStream(peer_id, stream)) |installed| {
                installed.retain();
                installed_stream = installed;
            } else {
                log.info("gossipsub: keeping existing peer stream for duplicate inbound stream", .{});
            }
            self.flushPendingSendsForPeer(io, peer_id);
            self.sendSubscriptionAnnouncement(peer_id);
            self.flushPendingSendsForPeer(io, peer_id);
            log.info("gossipsub: announced {d} subscriptions to inbound peer", .{self.tracked_subscriptions.count()});
        }

        var decoder = FrameDecoder.init(self.allocator);
        defer decoder.deinit();

        log.info("gossipsub inbound from peer ({d} bytes id)", .{peer_id.len});

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = stream.read(io, &buf) catch break;
            if (n == 0) break;
            log.debug("gossipsub: feeding {d} bytes to decoder (buf total: {d})", .{ n, decoder.buf.items.len + n });
            // Guard: if total buffered data exceeds max RPC size, skip
            if (decoder.buf.items.len + n > codec_mod.max_rpc_size) {
                log.warn("gossipsub: frame exceeds max RPC size, dropping", .{});
                decoder.deinit();
                decoder = FrameDecoder.init(self.allocator);
                continue;
            }
            decoder.feed(buf[0..n]) catch |err| {
                log.warn("gossipsub: feed error: {}", .{err});
                break;
            };
            while (decoder.next() catch null) |frame| {
                defer self.allocator.free(frame);
                log.debug("gossipsub: decoded frame of {d} bytes", .{frame.len});
                self.lock(io);
                self.router.handleRpc(peer_id, frame) catch |err| {
                    log.warn("gossipsub: handleRpc error: {}", .{err});
                };
                self.unlock(io);
            }
        }
    }

    /// Handle an outbound gossipsub stream.
    ///
    /// Stores the stream as an AnyStream keyed by peer ID. Router callbacks
    /// enqueue outbound RPCs through sendRpc; connection setup explicitly
    /// flushes queued data to the newly installed peer stream.
    pub fn handleOutbound(self: *Self, io: Io, stream: anytype, ctx: anytype) !void {
        const peer_id: []const u8 = if (@hasField(@TypeOf(ctx), "peer_id"))
            (ctx.peer_id orelse return)
        else
            return;

        self.lock(io);
        defer self.unlock(io);

        if ((try self.installPeerStream(peer_id, stream)) == null) {
            log.info("gossipsub: keeping existing peer stream for duplicate outbound stream", .{});
        }

        self.flushPendingSendsForPeer(io, peer_id);
        self.router.addPeer(peer_id) catch {};
        self.sendSubscriptionAnnouncement(peer_id);
        self.flushPendingSendsForPeer(io, peer_id);
    }

    /// Send a subscription announcement to a peer for all tracked subscriptions.
    fn sendSubscriptionAnnouncement(self: *Self, peer_id: []const u8) void {
        const count = self.tracked_subscriptions.count();
        if (count == 0) return;

        var sub_opts: [64]?rpc.RPC.SubOpts = undefined;
        var i: usize = 0;
        var iter = self.tracked_subscriptions.keyIterator();
        while (iter.next()) |key| {
            sub_opts[i] = .{ .subscribe = true, .topicid = key.* };
            i += 1;
            if (i == sub_opts.len) {
                self.sendSubscriptionAnnouncementChunk(peer_id, sub_opts[0..i]);
                i = 0;
            }
        }
        if (i != 0) {
            self.sendSubscriptionAnnouncementChunk(peer_id, sub_opts[0..i]);
        }
    }

    fn sendSubscriptionAnnouncementChunk(self: *Self, peer_id: []const u8, subscriptions: []const ?rpc.RPC.SubOpts) void {
        var rpc_msg = rpc.RPC{ .subscriptions = subscriptions };
        const frame = codec_mod.encodeRpc(self.allocator, &rpc_msg) catch return;
        defer self.allocator.free(frame);
        _ = self.sendRpc(peer_id, frame);
    }

    // ---------------------------------------------------------------
    // Router Handler interface (called by Router internally)
    // ---------------------------------------------------------------

    /// Send raw RPC bytes to a peer. Called by the Router.
    /// Enqueues outbound RPC data for later flushing by the integration layer.
    /// This keeps router callbacks (including validation-result reporting) from
    /// blocking on QUIC stream write readiness while holding gossipsub state.
    pub fn sendRpc(self: *Self, peer: []const u8, data: []const u8) bool {
        const peer_copy = self.allocator.dupe(u8, peer) catch return false;
        const data_copy = self.allocator.dupe(u8, data) catch {
            self.allocator.free(peer_copy);
            return false;
        };
        const queued_bytes = peer_copy.len + data_copy.len;
        if (self.pending_sends.items.len >= self.router.config.max_pending_sends or
            self.pending_send_bytes + queued_bytes > self.router.config.max_pending_send_bytes)
        {
            self.allocator.free(peer_copy);
            self.allocator.free(data_copy);
            log.warn("gossipsub: dropping outbound RPC because pending queue limits were reached", .{});
            return false;
        }
        self.pending_sends.append(self.allocator, .{
            .peer = peer_copy,
            .data = data_copy,
        }) catch {
            self.allocator.free(peer_copy);
            self.allocator.free(data_copy);
            return false;
        };
        self.pending_send_bytes += queued_bytes;
        return true;
    }

    fn flushPendingSendsForPeer(self: *Self, io: Io, peer_id: []const u8) void {
        const managed_stream = self.outbound_streams.get(peer_id) orelse return;

        managed_stream.retain();
        defer managed_stream.release(self.allocator);

        var i: usize = 0;
        while (i < self.pending_sends.items.len) {
            const pending = self.pending_sends.items[i];
            if (!std.mem.eql(u8, pending.peer, peer_id)) {
                i += 1;
                continue;
            }

            var total: usize = 0;
            var ok = true;
            while (total < pending.data.len) {
                const n = managed_stream.write(io, pending.data[total..]) catch {
                    ok = false;
                    break;
                };
                if (n == 0) {
                    ok = false;
                    break;
                }
                total += n;
            }

            if (!ok) {
                i += 1;
                continue;
            }

            const removed = self.pending_sends.orderedRemove(i);
            self.pending_send_bytes -= removed.peer.len + removed.data.len;
            self.allocator.free(removed.peer);
            self.allocator.free(removed.data);
        }
    }

    fn flushPendingSends(self: *Self, io: Io) void {
        var peer_iter = self.outbound_streams.keyIterator();
        while (peer_iter.next()) |peer_id| {
            self.flushPendingSendsForPeer(io, peer_id.*);
        }
    }

    fn dropPendingSendsForPeer(self: *Self, peer_id: []const u8) void {
        var i: usize = 0;
        while (i < self.pending_sends.items.len) {
            const pending = self.pending_sends.items[i];
            if (!std.mem.eql(u8, pending.peer, peer_id)) {
                i += 1;
                continue;
            }

            const removed = self.pending_sends.orderedRemove(i);
            self.pending_send_bytes -= removed.peer.len + removed.data.len;
            self.allocator.free(removed.peer);
            self.allocator.free(removed.data);
        }
    }

    /// Return a pseudo-random u64 using xorshift64.
    pub fn randomU64(self: *Self) u64 {
        var x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        return x;
    }

    /// Return the current time in milliseconds.
    pub fn currentTimeMs(self: *Self) u64 {
        return self.time_ms;
    }

    /// Check if a peer is currently connected.
    pub fn isPeerConnected(self: *Self, peer: []const u8) bool {
        return self.outbound_streams.contains(peer);
    }

    // ---------------------------------------------------------------
    // Public API — delegates to Router
    // ---------------------------------------------------------------

    /// Subscribe to a topic. Joins the mesh for this topic.
    pub fn subscribe(self: *Self, io: Io, topic: []const u8) !void {
        self.lock(io);
        defer self.unlock(io);
        try self.router.subscribe(topic);
        if (!self.tracked_subscriptions.contains(topic)) {
            const topic_copy = try self.allocator.dupe(u8, topic);
            self.tracked_subscriptions.put(topic_copy, {}) catch {
                self.allocator.free(topic_copy);
            };
        }
    }

    /// Unsubscribe from a topic. Leaves the mesh for this topic.
    pub fn unsubscribe(self: *Self, io: Io, topic: []const u8) !void {
        self.lock(io);
        defer self.unlock(io);
        try self.router.unsubscribe(topic);
        if (self.tracked_subscriptions.fetchRemove(topic)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    /// Publish a message to a topic.
    /// Returns the number of peers the message was sent to.
    pub fn publish(self: *Self, io: Io, topic: []const u8, data: []const u8) !u32 {
        self.lock(io);
        defer self.unlock(io);
        return try self.router.publish(topic, data);
    }

    /// Notify the Router that a new peer has connected.
    pub fn addPeer(self: *Self, io: Io, peer_id: []const u8) !void {
        self.lock(io);
        defer self.unlock(io);
        try self.router.addPeer(peer_id);
    }

    /// Notify the Router that a peer has disconnected.
    pub fn removePeer(self: *Self, io: Io, peer_id: []const u8) void {
        self.lock(io);
        defer self.unlock(io);
        if (self.outbound_streams.fetchRemove(peer_id)) |entry| {
            entry.value.close(io);
            entry.value.release(self.allocator);
            self.allocator.free(entry.key);
        }
        self.dropPendingSendsForPeer(peer_id);
        self.router.removePeer(peer_id);
    }

    /// Execute one heartbeat tick. Should be called periodically
    /// (e.g., every Config.heartbeat_interval_ms milliseconds).
    pub fn heartbeat(self: *Self, io: Io) !void {
        self.lock(io);
        defer self.unlock(io);
        try self.router.heartbeat();
        self.flushPendingSends(io);
    }

    /// Drain accumulated events from the Router.
    /// Caller owns the returned slice and must call `deinit()` on each event,
    /// then free the slice itself.
    pub fn drainEvents(self: *Self, io: Io) ![]Event {
        self.lock(io);
        defer self.unlock(io);
        return try self.router.drainEvents();
    }

    /// Report the consumer's validation result for a pending inbound message.
    pub fn reportValidationResult(
        self: *Self,
        io: Io,
        msg_id: []const u8,
        result: ValidationResult,
    ) bool {
        self.lock(io);
        defer self.unlock(io);
        return self.router.reportValidationResult(msg_id, result);
    }

    /// Pass a received RPC (protobuf bytes, without varint length prefix) to
    /// the Router for processing.
    pub fn handleRpc(self: *Self, io: Io, from_peer: []const u8, rpc_bytes: []const u8) !void {
        self.lock(io);
        defer self.unlock(io);
        try self.router.handleRpc(from_peer, rpc_bytes);
    }

    /// Drain all pending outbound RPCs. Caller owns the returned slice
    /// and must free each entry's `peer` and `data` slices, plus the slice itself.
    pub fn drainPendingSends(self: *Self, io: Io) []PendingRpc {
        self.lock(io);
        defer self.unlock(io);
        const drained = self.pending_sends.toOwnedSlice(self.allocator) catch return &.{};
        self.pending_send_bytes = 0;
        return drained;
    }

    /// Set the current time (for testing or external time source).
    pub fn setTime(self: *Self, io: Io, ms: u64) void {
        self.lock(io);
        defer self.unlock(io);
        self.time_ms = ms;
    }

    /// Set the PRNG seed.
    pub fn setSeed(self: *Self, io: Io, seed: u64) void {
        self.lock(io);
        defer self.unlock(io);
        self.rng_state = seed;
    }
};

/// Handler wraps a heap-allocated Service for embedding in Switch's HandlerTuple.
/// The Service is heap-allocated (self-referential: Router stores *Handler -> *Service).
/// This thin wrapper stores a pointer to the Service and is safe to embed by value.
pub const Handler = struct {
    svc: *Service,

    pub const id = Service.id;

    pub fn handleInbound(self: *Handler, io: Io, stream: anytype, ctx: anytype) !void {
        try self.svc.handleInbound(io, stream, ctx);
    }

    pub fn handleOutbound(self: *Handler, io: Io, stream: anytype, ctx: anytype) !void {
        try self.svc.handleOutbound(io, stream, ctx);
    }

    /// Called by the Switch when a connection to this peer closes.
    /// Matches rust-libp2p's on_connection_closed / FromSwarm::ConnectionClosed.
    pub fn onPeerDisconnected(self: *Handler, io: Io, peer_id: []const u8) void {
        self.svc.removePeer(io, peer_id);
    }
};

// --- Tests ---

/// A message ID function that uses topic + data instead of from + seqno.
/// Suitable for testing with strict_no_sign / anonymous policies where
/// the router does not populate from/seqno on publish.
fn testMsgId(allocator: Allocator, msg: *const rpc.Message) anyerror![]const u8 {
    return std.mem.concat(allocator, u8, &.{ msg.topic orelse "", msg.data orelse "" });
}

/// Test config that does not require from/seqno for message IDs.
const test_config: Config = .{
    .signature_policy = .strict_no_sign,
    .publish_policy = .anonymous,
    .msg_id_fn = testMsgId,
};

test "Service init and deinit" {
    const svc = try Service.init(std.testing.allocator, .{});
    defer svc.deinit(std.testing.io);
}

test "Service subscribe and unsubscribe" {
    const svc = try Service.init(std.testing.allocator, .{});
    defer svc.deinit(std.testing.io);

    try svc.subscribe(std.testing.io, "test-topic");
    try svc.unsubscribe(std.testing.io, "test-topic");
}

test "Service subscribe, publish, heartbeat" {
    const svc = try Service.init(std.testing.allocator, test_config);
    defer svc.deinit(std.testing.io);

    try svc.subscribe(std.testing.io, "test-topic");

    // Add a peer and publish
    try svc.addPeer(std.testing.io, "peer-1");

    // Run heartbeat to establish mesh
    svc.setTime(std.testing.io, 1000);
    try svc.heartbeat(std.testing.io);

    // Publish a message
    _ = try svc.publish(std.testing.io, "test-topic", "hello");

    // Check pending sends
    const sends = svc.drainPendingSends(std.testing.io);
    defer {
        for (sends) |s| {
            svc.allocator.free(s.peer);
            svc.allocator.free(s.data);
        }
        svc.allocator.free(sends);
    }

    try svc.unsubscribe(std.testing.io, "test-topic");
    svc.removePeer(std.testing.io, "peer-1");
}

test "Service drainPendingSends returns empty when nothing pending" {
    const svc = try Service.init(std.testing.allocator, .{});
    defer svc.deinit(std.testing.io);

    const sends = svc.drainPendingSends(std.testing.io);
    try std.testing.expectEqual(@as(usize, 0), sends.len);
    svc.allocator.free(sends);
}

test "Service sendRpc enforces pending queue limits" {
    const svc = try Service.init(std.testing.allocator, .{
        .max_pending_sends = 1,
        .max_pending_send_bytes = 16,
    });
    defer svc.deinit(std.testing.io);

    try std.testing.expect(svc.sendRpc("peer-1", "1234"));
    try std.testing.expect(!svc.sendRpc("peer-2", "5678"));
    try std.testing.expectEqual(@as(usize, 1), svc.pending_sends.items.len);

    const sends = svc.drainPendingSends(std.testing.io);
    defer {
        for (sends) |s| {
            svc.allocator.free(s.peer);
            svc.allocator.free(s.data);
        }
        svc.allocator.free(sends);
    }
    try std.testing.expectEqual(@as(usize, 1), sends.len);
    try std.testing.expectEqual(@as(usize, 0), svc.pending_send_bytes);
}

const RecordingStream = struct {
    const Self = @This();

    writes: *std.ArrayList(u8),

    pub fn read(_: *Self, _: Io, _: []u8) !usize {
        return 0;
    }

    pub fn write(self: *Self, _: Io, data: []const u8) !usize {
        try self.writes.appendSlice(std.testing.allocator, data);
        return data.len;
    }

    pub fn closeRead(_: *Self, _: Io) void {}
    pub fn closeWrite(_: *Self, _: Io) void {}
    pub fn close(_: *Self, _: Io) void {}
    pub fn deinit(_: *Self) void {}

    pub fn detachOwnedStream(self: *Self) Self {
        return self.*;
    }
};

test "Service sendRpc queues instead of writing from router callbacks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const svc = try Service.init(allocator, .{});
    defer svc.deinit(io);

    var writes: std.ArrayList(u8) = .empty;
    defer writes.deinit(allocator);
    var stream = RecordingStream{ .writes = &writes };
    try svc.handleOutbound(io, &stream, .{ .peer_id = @as(?[]const u8, "peer-1") });

    try std.testing.expect(svc.sendRpc("peer-1", "queued-rpc"));

    try std.testing.expectEqual(@as(usize, 1), svc.pending_sends.items.len);
    try std.testing.expectEqual(@as(usize, 0), writes.items.len);
}

test "Service flushes queued RPCs when a peer stream is installed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const svc = try Service.init(allocator, .{});
    defer svc.deinit(io);

    try std.testing.expect(svc.sendRpc("peer-1", "queued-rpc"));
    try std.testing.expectEqual(@as(usize, 1), svc.pending_sends.items.len);

    var writes: std.ArrayList(u8) = .empty;
    defer writes.deinit(allocator);
    var stream = RecordingStream{ .writes = &writes };

    try svc.handleOutbound(io, &stream, .{ .peer_id = @as(?[]const u8, "peer-1") });

    try std.testing.expectEqual(@as(usize, 0), svc.pending_sends.items.len);
    try std.testing.expectEqual(@as(usize, 0), svc.pending_send_bytes);
    try std.testing.expectEqualStrings("queued-rpc", writes.items);
}

test "Service announces more than 64 tracked subscriptions to newly connected peers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const TestStream = struct {
        const Self = @This();

        writes: *std.ArrayList(u8),

        pub fn read(_: *Self, _: Io, _: []u8) !usize {
            return 0;
        }

        pub fn write(self: *Self, _: Io, data: []const u8) !usize {
            try self.writes.appendSlice(std.testing.allocator, data);
            return data.len;
        }

        pub fn closeRead(_: *Self, _: Io) void {}
        pub fn closeWrite(_: *Self, _: Io) void {}
        pub fn close(_: *Self, _: Io) void {}
        pub fn deinit(_: *Self) void {}

        pub fn detachOwnedStream(self: *Self) Self {
            return self.*;
        }
    };

    const svc = try Service.init(allocator, .{});
    defer svc.deinit(io);

    for (0..65) |i| {
        const topic = try std.fmt.allocPrint(allocator, "topic-{d}", .{i});
        defer allocator.free(topic);
        try svc.subscribe(io, topic);
    }

    var writes: std.ArrayList(u8) = .empty;
    defer writes.deinit(allocator);
    var stream = TestStream{ .writes = &writes };
    try svc.handleOutbound(io, &stream, .{ .peer_id = @as(?[]const u8, "peer-1") });

    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();
    try decoder.feed(writes.items);

    var topic_count: usize = 0;
    var frame_count: usize = 0;
    while (try decoder.next()) |frame| {
        defer allocator.free(frame);
        frame_count += 1;
        var reader = try rpc.RPCReader.init(frame);
        while (reader.subscriptionsNext()) |_| {
            topic_count += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 2), frame_count);
    try std.testing.expectEqual(@as(usize, 65), topic_count);
}

test "Service removePeer drops queued RPCs for that peer" {
    const svc = try Service.init(std.testing.allocator, .{});
    defer svc.deinit(std.testing.io);

    try std.testing.expect(svc.sendRpc("peer-1", "queued-a"));
    try std.testing.expect(svc.sendRpc("peer-2", "queued-b"));
    try std.testing.expectEqual(@as(usize, 2), svc.pending_sends.items.len);

    svc.removePeer(std.testing.io, "peer-1");

    try std.testing.expectEqual(@as(usize, 1), svc.pending_sends.items.len);
    try std.testing.expectEqualStrings("peer-2", svc.pending_sends.items[0].peer);
    try std.testing.expectEqual(@as(usize, "peer-2".len + "queued-b".len), svc.pending_send_bytes);
}

test "Service setTime and setSeed" {
    const svc = try Service.init(std.testing.allocator, .{});
    defer svc.deinit(std.testing.io);

    svc.setTime(std.testing.io, 42000);
    try std.testing.expectEqual(@as(u64, 42000), svc.currentTimeMs());

    svc.setSeed(std.testing.io, 99);
    const r1 = svc.randomU64();
    const r2 = svc.randomU64();
    try std.testing.expect(r1 != r2);
}

test "Service randomU64 is deterministic for same seed" {
    const svc = try Service.init(std.testing.allocator, .{});
    defer svc.deinit(std.testing.io);

    svc.setSeed(std.testing.io, 12345);
    const a1 = svc.randomU64();
    const a2 = svc.randomU64();

    svc.setSeed(std.testing.io, 12345);
    const b1 = svc.randomU64();
    const b2 = svc.randomU64();

    try std.testing.expectEqual(a1, b1);
    try std.testing.expectEqual(a2, b2);
}

test "Service protocol id matches meshsub v1.2" {
    try std.testing.expectEqualStrings("/meshsub/1.2.0", Service.id);
}

test "Service publish generates pending sends to mesh peers" {
    const svc = try Service.init(std.testing.allocator, test_config);
    defer svc.deinit(std.testing.io);

    try svc.subscribe(std.testing.io, "topic-a");
    try svc.addPeer(std.testing.io, "peer-1");
    try svc.addPeer(std.testing.io, "peer-2");

    // Subscribe peers to the topic so they are eligible for mesh
    var subs = [_]?rpc.RPC.SubOpts{
        .{ .subscribe = true, .topicid = "topic-a" },
    };
    var rpc_msg = rpc.RPC{ .subscriptions = &subs };
    const encoded = rpc_msg.encode(std.testing.allocator) catch unreachable;
    defer std.testing.allocator.free(encoded);
    try svc.handleRpc(std.testing.io, "peer-1", encoded);
    try svc.handleRpc(std.testing.io, "peer-2", encoded);

    // Heartbeat to graft peers into mesh
    svc.setTime(std.testing.io, 1000);
    try svc.heartbeat(std.testing.io);

    // Clear any sends from heartbeat (GRAFT messages)
    const heartbeat_sends = svc.drainPendingSends(std.testing.io);
    for (heartbeat_sends) |s| {
        svc.allocator.free(s.peer);
        svc.allocator.free(s.data);
    }
    svc.allocator.free(heartbeat_sends);

    // Publish a message
    const sent_count = try svc.publish(std.testing.io, "topic-a", "test-data");
    try std.testing.expect(sent_count > 0);

    // Verify pending sends were generated
    const sends = svc.drainPendingSends(std.testing.io);
    defer {
        for (sends) |s| {
            svc.allocator.free(s.peer);
            svc.allocator.free(s.data);
        }
        svc.allocator.free(sends);
    }
    try std.testing.expect(sends.len > 0);
}

test "duplicate inbound peer stream keeps original installed stream" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const TestStream = struct {
        const Self = @This();

        id: u8,
        deinit_count: ?*usize,

        pub fn read(_: *Self, _: Io, _: []u8) !usize {
            return 0;
        }

        pub fn write(_: *Self, _: Io, data: []const u8) !usize {
            return data.len;
        }

        pub fn closeRead(_: *Self, _: Io) void {}
        pub fn closeWrite(_: *Self, _: Io) void {}
        pub fn close(_: *Self, _: Io) void {}

        pub fn deinit(self: *Self) void {
            const counter = self.deinit_count orelse return;
            counter.* += 1;
            self.deinit_count = null;
        }

        pub fn detachOwnedStream(self: *Self) Self {
            const detached = self.*;
            self.deinit_count = null;
            return detached;
        }
    };

    const svc = try Service.init(allocator, .{});
    defer svc.deinit(io);

    var deinit_count: usize = 0;
    var stream_a = TestStream{ .id = 1, .deinit_count = &deinit_count };
    var stream_b = TestStream{ .id = 2, .deinit_count = &deinit_count };

    try svc.handleInbound(io, &stream_a, .{ .peer_id = @as(?[]const u8, "peer-1") });
    try std.testing.expectEqual(@as(usize, 0), deinit_count);
    try std.testing.expect(svc.outbound_streams.contains("peer-1"));

    const stored_before = svc.outbound_streams.get("peer-1").?;
    const first_backing = @as(*TestStream, @ptrCast(@alignCast(stored_before.owned.backing_ptr)));
    try std.testing.expectEqual(@as(u8, 1), first_backing.id);

    try svc.handleInbound(io, &stream_b, .{ .peer_id = @as(?[]const u8, "peer-1") });
    try std.testing.expectEqual(@as(usize, 0), deinit_count);

    const stored_after = svc.outbound_streams.get("peer-1").?;
    const second_backing = @as(*TestStream, @ptrCast(@alignCast(stored_after.owned.backing_ptr)));
    try std.testing.expectEqual(@as(u8, 1), second_backing.id);

    svc.removePeer(io, "peer-1");
    try std.testing.expectEqual(@as(usize, 1), deinit_count);
}

test "removePeer defers stream destruction until active inbound handler exits" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const BlockingStream = struct {
        const Self = @This();

        close_count: *usize,
        deinit_count: ?*usize,
        started: *Io.Event,
        finish: *Io.Event,
        started_once: bool = false,

        pub fn read(self: *Self, read_io: Io, _: []u8) !usize {
            if (!self.started_once) {
                self.started_once = true;
                self.started.set(read_io);
            }
            try self.finish.wait(read_io);
            return 0;
        }

        pub fn write(_: *Self, _: Io, data: []const u8) !usize {
            return data.len;
        }

        pub fn closeRead(_: *Self, _: Io) void {}
        pub fn closeWrite(_: *Self, _: Io) void {}

        pub fn close(self: *Self, _: Io) void {
            self.close_count.* += 1;
        }

        pub fn deinit(self: *Self) void {
            const counter = self.deinit_count orelse return;
            counter.* += 1;
            self.deinit_count = null;
        }

        pub fn detachOwnedStream(self: *Self) Self {
            const detached = self.*;
            self.deinit_count = null;
            return detached;
        }
    };

    const Runner = struct {
        fn run(svc: *Service, runner_io: Io, stream: *BlockingStream, done: *Io.Event) void {
            defer done.set(runner_io);
            svc.handleInbound(runner_io, stream, .{ .peer_id = @as(?[]const u8, "peer-1") }) catch {};
        }
    };

    const svc = try Service.init(allocator, .{});
    defer svc.deinit(io);

    var started: Io.Event = .unset;
    var finish: Io.Event = .unset;
    var done: Io.Event = .unset;
    var close_count: usize = 0;
    var deinit_count: usize = 0;
    var stream = BlockingStream{
        .close_count = &close_count,
        .deinit_count = &deinit_count,
        .started = &started,
        .finish = &finish,
    };
    var group: Io.Group = .init;

    group.async(io, Runner.run, .{ svc, io, &stream, &done });
    try started.wait(io);

    svc.removePeer(io, "peer-1");
    try std.testing.expectEqual(@as(usize, 1), close_count);
    try std.testing.expectEqual(@as(usize, 0), deinit_count);

    finish.set(io);
    try done.wait(io);
    try std.testing.expectEqual(@as(usize, 1), deinit_count);
}
