const std = @import("std");
const utils = @import("utils.zig");
const AttributeInfo = @import("attributes.zig").AttributeInfo;
const ConstantPool = @import("ConstantPool.zig");

const MethodInfo = @This();

pub const AccessFlags = struct {
    public: bool = false,
    private: bool = false,
    protected: bool = false,
    static: bool = false,
    final: bool = false,
    synchronized: bool = false,
    bridge: bool = false,
    varargs: bool = false,
    native: bool = false,
    abstract: bool = false,
    strict: bool = false,
    synthetic: bool = false,
};

constant_pool: *ConstantPool,

access_flags: AccessFlags,
name_index: u16,
descriptor_index: u16,
attributes: std.ArrayList(AttributeInfo),

pub fn getName(self: MethodInfo) ConstantPool.Utf8Info {
    return self.constant_pool.get(self.name_index).utf8;
}

pub fn getDescriptor(self: MethodInfo) ConstantPool.Utf8Info {
    return self.constant_pool.get(self.descriptor_index).utf8;
}

pub fn format(self: MethodInfo, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    try writer.print("MethodInfo({s} {s})", .{ self.getName().bytes, self.getDescriptor().bytes });
}

pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !MethodInfo {
    const access_flags_u = try reader.readInt(u16, .big);
    const name_index = try reader.readInt(u16, .big);
    const descriptor_index = try reader.readInt(u16, .big);

    var attributes_length = try reader.readInt(u16, .big);
    var attributes_index: usize = 0;
    var attributess = std.ArrayList(AttributeInfo).init(allocator);
    while (attributes_index < attributes_length) : (attributes_index += 1) {
        const decoded = try AttributeInfo.decode(constant_pool, allocator, reader);
        if (decoded == .unknown) {
            attributes_length -= 1;
            continue;
        }
        try attributess.append(decoded);
    }

    return MethodInfo{
        .constant_pool = constant_pool,

        .access_flags = .{
            .public = utils.isPresent(u16, access_flags_u, 0x0001),
            .private = utils.isPresent(u16, access_flags_u, 0x0002),
            .protected = utils.isPresent(u16, access_flags_u, 0x0004),
            .static = utils.isPresent(u16, access_flags_u, 0x0008),
            .final = utils.isPresent(u16, access_flags_u, 0x0010),
            .synchronized = utils.isPresent(u16, access_flags_u, 0x0020),
            .bridge = utils.isPresent(u16, access_flags_u, 0x0040),
            .varargs = utils.isPresent(u16, access_flags_u, 0x0080),
            .native = utils.isPresent(u16, access_flags_u, 0x0100),
            .abstract = utils.isPresent(u16, access_flags_u, 0x0400),
            .strict = utils.isPresent(u16, access_flags_u, 0x0800),
            .synthetic = utils.isPresent(u16, access_flags_u, 0x1000),
        },
        .name_index = name_index,
        .descriptor_index = descriptor_index,
        .attributes = attributess,
    };
}

pub fn encode(self: MethodInfo, writer: anytype) !void {
    var access_flags_u: u16 = 0;
    if (self.access_flags.public) utils.setPresent(u16, &access_flags_u, 0x0001);
    if (self.access_flags.private) utils.setPresent(u16, &access_flags_u, 0x0002);
    if (self.access_flags.protected) utils.setPresent(u16, &access_flags_u, 0x0004);
    if (self.access_flags.static) utils.setPresent(u16, &access_flags_u, 0x0008);
    if (self.access_flags.final) utils.setPresent(u16, &access_flags_u, 0x0010);
    if (self.access_flags.synchronized) utils.setPresent(u16, &access_flags_u, 0x0020);
    if (self.access_flags.bridge) utils.setPresent(u16, &access_flags_u, 0x0040);
    if (self.access_flags.varargs) utils.setPresent(u16, &access_flags_u, 0x0080);
    if (self.access_flags.native) utils.setPresent(u16, &access_flags_u, 0x0100);
    if (self.access_flags.abstract) utils.setPresent(u16, &access_flags_u, 0x0400);
    if (self.access_flags.strict) utils.setPresent(u16, &access_flags_u, 0x0800);
    if (self.access_flags.synthetic) utils.setPresent(u16, &access_flags_u, 0x1000);
    try writer.writeInt(u16, access_flags_u, .big);

    try writer.writeInt(u16, self.name_index, .big);
    try writer.writeInt(u16, self.descriptor_index, .big);

    try writer.writeInt(u16, @as(u16, @intCast(self.attributes.items.len)), .big);
    for (self.attributes.items) |*att| try att.encode(writer);
}

pub fn deinit(self: MethodInfo) void {
    for (self.attributes.items) |*att| att.deinit();
    self.attributes.deinit();
}
