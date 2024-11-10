const std = @import("std");
const utils = @import("utils.zig");
const AttributeInfo = @import("attributes.zig").AttributeInfo;
const ConstantPool = @import("ConstantPool.zig");

const MethodInfo = @This();

pub const AccessFlagsValue = enum(u16) {
    public = 0x0001,
    private = 0x0002,
    protected = 0x004,
    static = 0x0008,
    final = 0x0010,
    synchronized = 0x0020,
    bridge = 0x040,
    varargs = 0x0080,
    native = 0x0100,
    abstract = 0x0400,
    strict = 0x0800,
    synthetic = 0x1000,

    pub fn name(flag: AccessFlagsValue) []const u8 {
        return switch (flag) {
            .public => "ACC_PUBLIC",
            .private => "ACC_PRIVATE",
            .protected => "ACC_PROTECTED",
            .static => "ACC_STATIC",
            .final => "ACC_FINAL",
            .synchronized => "ACC_SYNCHRONIZED",
            .bridge => "ACC_BRIDGE",
            .varargs => "ACC_VARARGS",
            .native => "ACC_NATIVE",
            .abstract => "ACC_ABSTRACT",
            .strict => "ACC_STRICT",
            .synthetic => "ACC_SYNTHETIC",
        };
    }

    pub fn keyword(flag: AccessFlagsValue) []const u8 {
        return switch (flag) {
            .public => "public",
            .private => "private",
            .protected => "protected",
            .static => "static",
            .final => "final",
            .synchronized => "synchronized",
            .bridge => "bridge",
            .varargs => "vargargs",
            .native => "native",
            .abstract => "abstract",
            .strict => "strict",
            .synthetic => "synthetic",
        };
    }
};

pub const AccessFlagsFields = packed struct {
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

const AccessFlagsIter = utils.EnumIter(AccessFlagsValue);

pub const AccessFlags = packed union {
    value: u16,
    flags: AccessFlagsFields,

    pub fn iter(it: AccessFlags) AccessFlagsIter {
        return AccessFlagsIter{
            .value = it.value,
        };
    }

    pub fn count(it: AccessFlags) usize {
        return @popCount(it.value);
    }
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
    try writer.print("MethodInfo({s} {s})", .{
        self.getName().bytes,
        self.getDescriptor().bytes,
    });
}

pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !MethodInfo {
    const access_flags_u = try reader.readInt(u16, .big);
    const name_index = try reader.readInt(u16, .big);
    const descriptor_index = try reader.readInt(u16, .big);

    const attributes_length = try reader.readInt(u16, .big);
    var attributes_index: usize = 0;
    var attributess = std.ArrayList(AttributeInfo).init(allocator);
    while (attributes_index < attributes_length) : (attributes_index += 1) {
        const decoded = try AttributeInfo.decode(constant_pool, allocator, reader);
        try attributess.append(decoded);
    }

    return MethodInfo{
        .constant_pool = constant_pool,
        .access_flags = AccessFlags{ .value = access_flags_u },
        .name_index = name_index,
        .descriptor_index = descriptor_index,
        .attributes = attributess,
    };
}

pub fn encode(self: MethodInfo, writer: anytype, constant_pool: *ConstantPool) !void {
    try writer.writeInt(u16, self.access_flags.value, .big);

    try writer.writeInt(u16, self.name_index, .big);
    try writer.writeInt(u16, self.descriptor_index, .big);

    try writer.writeInt(u16, @as(u16, @intCast(self.attributes.items.len)), .big);
    for (self.attributes.items) |*att| try att.encode(writer, constant_pool);
}

pub fn deinit(self: MethodInfo) void {
    for (self.attributes.items) |*att| att.deinit();
    self.attributes.deinit();
}
