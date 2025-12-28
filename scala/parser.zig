const std = @import("std");

const scala = @import(".");

const Allocator = std.mem.Allocator;
const Token = @import("tokenizer.zig").Token;

gpa: Allocator,
source: [:0]const u8,

fn tokenTag(p: *const Parser, token_index: TokenIndex) Token.Tag {
    return p.tokens.times[token_index].tag;
}

const Parser = @This();
const Ast = @import("ast.zig");
const TokenIndex = Ast.TokenIndex;

test {
    _ = @import("parser_test.zig");
}
