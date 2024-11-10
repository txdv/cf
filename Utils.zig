const std = @import("std");

pub const FileData = struct {
    path_buffer: [std.fs.MAX_PATH_BYTES]u8,
    path: []u8,
    data: []const u8,
    mtime: i128,

    pub fn free(it: FileData, allocator: std.mem.Allocator) void {
        _ = it;
        _ = allocator;
    }
};

pub fn readFileData(allocator: std.mem.Allocator, filename: []const u8, file_data: *FileData) !void {
    file_data.path = try std.fs.realpath(filename, &file_data.path_buffer);
    file_data.path_buffer[file_data.path.len] = 0;
    file_data.path = file_data.path_buffer[0..file_data.path.len];

    const file = try std.fs.openFileAbsolute(file_data.path, .{});
    const stat = try file.stat();
    file_data.mtime = stat.mtime;

    const max_bytes = 1024 * 4096 * 4095;
    file_data.data = try file.readToEndAlloc(allocator, max_bytes);
}

pub fn getFilename() []const u8 {
    if (std.os.argv.len < 2) {
        _ = std.io.getStdErr().writer().print("Specify a file\n", .{}) catch {};
        unreachable;
        //return error.FileNotFound;
    }
    const filename = std.os.argv[1];
    const filename_length = std.mem.len(filename);
    return filename[0..filename_length];
}
