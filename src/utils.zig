const std = @import("std");

pub fn isPresent(comptime T: type, u: T, c: T) bool {
    return u & c == c;
}

pub fn setPresent(comptime T: type, value: *T, thang: T) void {
    value.* |= thang;
}

pub fn EnumIter(comptime E: anytype) type {
    const values = std.enums.values(E);

    return struct {
        const Self = @This();
        array: []const E = values,
        index: u32 = 0,
        value: u16,

        pub fn next(it: *Self) ?E {
            if (it.index >= it.array.len) return null;
            while (@intFromEnum(it.array[it.index]) & it.value == 0) {
                it.index += 1;
                if (it.index >= it.array.len) return null;
            }

            const value = it.array[it.index];

            it.index += 1;

            return value;
        }
    };
}
