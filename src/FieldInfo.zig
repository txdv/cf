const std = @import("std");
const utils = @import("utils.zig");
const AttributeInfo = @import("attributes.zig").AttributeInfo;
const ClassFile = @import("ClassFile.zig");
const ConstantPool = @import("ConstantPool.zig");

const FieldInfo = @This();

pub const AccessFlagsValue = enum(u16) {
    public = 0x0001,
    private = 0x0002,
    protected = 0x004,
    static = 0x0008,
    final = 0x0010,
    @"volatile" = 0x0040,
    transient = 0x0080,
    synthetic = 0x1000,
    @"enum" = 0x4000,

    pub fn name(flag: AccessFlagsValue) []const u8 {
        return switch (flag) {
            .public => "ACC_PUBLIC",
            .private => "ACC_PRIVATE",
            .protected => "ACC_PROTECTED",
            .static => "ACC_STATIC",
            .final => "ACC_FINAL",
            .@"volatile" => "ACC_VOLATILE",
            .transient => "ACC_TRANSIENT",
            .synthetic => "ACC_SYNTHETIC",
            .@"enum" => "ACC_ENUM",
        };
    }

    pub fn keyword(flag: AccessFlagsValue) []const u8 {
        return switch (flag) {
            .public => "public",
            .private => "private",
            .protected => "protected",
            .static => "static",
            .final => "final",
            .@"volatile" => "volatile",
            .transient => "transient",
            .synthetic => "synthetic",
            .@"enum" => "enum",
        };
    }
};

pub const AccessFlagsFields = packed struct {
    public: bool = false,
    private: bool = false,
    protected: bool = false,
    static: bool = false,
    final: bool = false,
    @"volatile": bool = false,
    transient: bool = false,
    synthetic: bool = false,
    enum_member: bool = false,
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
};

constant_pool: *ConstantPool,

access_flags: AccessFlags,
name_index: u16,
descriptor_index: u16,
attributes: std.ArrayList(AttributeInfo),

pub fn getName(self: FieldInfo) ConstantPool.Utf8Info {
    return self.constant_pool.get(self.name_index).utf8;
}

pub fn getDescriptor(self: FieldInfo) ConstantPool.Utf8Info {
    return self.constant_pool.get(self.descriptor_index).utf8;
}

pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !FieldInfo {
    const access_flags_u = try reader.readInt(u16, .big);
    const name_index = try reader.readInt(u16, .big);
    const descriptor_index = try reader.readInt(u16, .big);

    // var att_count = try reader.readInt(u16, .big);
    // var att = try std.ArrayList(AttributeInfo).initCapacity(allocator, att_count);
    // for (att.items) |*a| a.* = try AttributeInfo.decode(constant_pool, allocator, reader);
    var attributes_length = try reader.readInt(u16, .big);
    var attributes_index: usize = 0;
    var attributes = std.ArrayList(AttributeInfo).init(allocator);
    while (attributes_index < attributes_length) : (attributes_index += 1) {
        const decoded = try AttributeInfo.decode(constant_pool, allocator, reader);
        if (decoded == .unknown) {
            attributes_length -= 1;
            continue;
        }
        try attributes.append(decoded);
    }

    return FieldInfo{
        .constant_pool = constant_pool,

        .access_flags = AccessFlags{ .value = access_flags_u },
        .name_index = name_index,
        .descriptor_index = descriptor_index,
        .attributes = attributes,
    };
}

pub fn encode(self: FieldInfo, writer: anytype) !void {
    var access_flags_u: u16 = 0;
    if (self.access_flags.public) utils.setPresent(u16, &access_flags_u, 0x0001);
    if (self.access_flags.private) utils.setPresent(u16, &access_flags_u, 0x0002);
    if (self.access_flags.protected) utils.setPresent(u16, &access_flags_u, 0x0004);
    if (self.access_flags.static) utils.setPresent(u16, &access_flags_u, 0x0008);
    if (self.access_flags.final) utils.setPresent(u16, &access_flags_u, 0x0010);
    if (self.access_flags.@"volatile") utils.setPresent(u16, &access_flags_u, 0x0040);
    if (self.access_flags.transient) utils.setPresent(u16, &access_flags_u, 0x0080);
    if (self.access_flags.synthetic) utils.setPresent(u16, &access_flags_u, 0x1000);
    if (self.access_flags.enum_member) utils.setPresent(u16, &access_flags_u, 0x4000);
    try writer.writeInt(u16, access_flags_u, .big);

    try writer.writeInt(u16, self.name_index, .big);
    try writer.writeInt(u16, self.descriptor_index, .big);

    const attributes_len = @as(u16, @intCast(self.attributes.items.len));
    try writer.writeInt(u16, attributes_len, .big);
    for (self.attributes.items) |*att| try att.encode(writer);
}

pub fn deinit(self: FieldInfo) void {
    for (self.attributes.items) |*att| att.deinit();
    self.attributes.deinit();
}
