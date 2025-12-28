const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const Tokenizer = tokenizer.Tokenizer;
const Token = tokenizer.Token;

fn readSourceFromArgs(allocator: std.mem.Allocator) ![:0]u8 {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <filename>\n", .{args[0]});
        return error.MissingFilename;
    }

    const filename = args[1];

    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const file_size = (try file.stat()).size;
    const buffer = try allocator.allocSentinel(u8, file_size, 0);
    errdefer allocator.free(buffer);

    _ = try file.readAll(buffer);

    return buffer;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const buffer = try readSourceFromArgs(allocator);
    defer allocator.free(buffer);

    // Initialize tokenizer
    var tok = Tokenizer.init(buffer);

    // Get stdout writer
    var stdout_buffer: [4096]u8 = undefined;
    const stdout = std.fs.File.stdout();
    var file_writer = stdout.writer(&stdout_buffer);
    const writer = &file_writer.interface;

    // Tokenize and print all tokens
    while (true) {
        const token = tok.next();

        // Print token tag
        try writer.print("{s}", .{@tagName(token.tag)});

        // Print token text if available
        if (token.loc.start < token.loc.end) {
            const text = buffer[token.loc.start..token.loc.end];
            try writer.print(" '{s}'", .{text});
        }

        try writer.print(" ({d}..{d})\n", .{token.loc.start, token.loc.end});

        if (token.tag == .eof) {
            break;
        }
    }

    try writer.flush();
}
