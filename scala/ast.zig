const std = @import("std");
const Token = @import("tokenizer.zig").Token;
const Tokenizer = @import("tokenizer.zig").Tokenizer;
const Parser = @import("parser.zig");

const Ast = @This();
const Allocator = std.mem.Allocator;

tokens: TokenList.Slice,

pub const ByteOffset = u32;

pub const TokenList = std.MultiArrayList(struct {
    tag: Token.Tag,
    start: ByteOffset,
});

pub const TokenIndex = u32;

pub fn parse(gpa: Allocator, source: [:0]const u8) Allocator.Error!Ast {
    var tokens = Ast.TokenList{};
    defer tokens.deinit(gpa);

    var tokenizer = Tokenizer.init(source);
    while (true) {
        const token = tokenizer.next();
        try tokens.append(gpa, .{
            .tag = token.tag,
            .start = @intCast(token.loc.start),
        });
        if (token.tag == Token.Tag.eof) break;
    }

    return Ast{
        .tokens = tokens.toOwnedSlice(),
    };
}

const hello_world =
    \\object Main {
    \\  def main(args: Array[String]): Unit = {
    \\    println("Hello World!")
    \\  }
    \\}
;

test "create ast for simple hello world" {
    const gpa = std.testing.allocator;
    var p = try parse(gpa, hello_world);
    p.tokens.deinit(gpa);
    try std.testing.expectEqual(1, 1);
}
