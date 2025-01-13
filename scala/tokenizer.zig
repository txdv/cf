const std = @import("std");

pub const Token = struct {
    tag: Tag,
    loc: Loc,

    pub const Loc = struct {
        start: usize,
        end: usize,
    };

    pub const keywords = std.StaticStringMap(Tag).initComptime(.{
        .{ "object", .keyword_object },
        .{ "def", .keyword_object },
    });

    pub fn getKeyword(bytes: []const u8) ?Tag {
        return keywords.get(bytes);
    }

    pub const Tag = enum {
        invalid,
        number_literal,
        identifier,
        l_brace,
        r_brace,
        eof,
        keyword_object,
        keyword_def,

        pub fn lexeme(tag: Tag) ?[]const u8 {
            return switch (tag) {
                .invalid,
                .number_literal,
                .eof,
                => null,
                .keyword_object => "object",
            };
        }
    };

    pub const Tokenizer = struct {
        buffer: [:0]const u8,
        index: usize,

        pub fn init(buffer: [:0]const u8) Tokenizer {
            return .{
                .buffer = buffer,
                .index = if (std.mem.startsWith(u8, buffer, "\xEF\xBB\xBF")) 3 else 0,
            };
        }

        const State = enum {
            start,
            identifier,
            int,
            invalid,
        };

        pub fn next(self: *Tokenizer) Token {
            var state: State = .start;
            var result: Token = .{
                .tag = undefined,
                .loc = .{
                    .start = self.index,
                    .end = undefined,
                },
            };
            state: switch (State.start) {
                .start => switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index == self.buffer.len) return .{
                            .tag = .eof,
                            .loc = .{
                                .start = self.index,
                                .end = self.index,
                            },
                        };
                        state = .invalid;
                    },
                    '{' => {
                        result.tag = .l_brace;
                        self.index += 1;
                    },
                    '}' => {
                        result.tag = .r_brace;
                        self.index += 1;
                    },
                    'a'...'z', 'A'...'Z', '_' => {
                        result.tag = .identifier;
                        continue :state .identifier;
                    },
                    '0'...'9' => {
                        result.tag = .number_literal;
                        continue :state .int;
                    },
                    else => unreachable,
                },
                .identifier => {
                    self.index += 1;
                    switch (self.buffer[self.index]) {
                        'a'...'z', 'A'...'Z', '_', '0'...'9' => continue :state .identifier,
                        else => {
                            const ident = self.buffer[result.loc.start..self.index];
                            if (Token.getKeyword(ident)) |tag| {
                                result.tag = tag;
                            }
                        },
                    }
                },
                .int => switch (self.buffer[self.index]) {
                    '0'...'9' => {
                        self.index += 1;
                        continue :state .int;
                    },
                    else => {},
                },
                else => unreachable,
            }

            result.loc.end = self.index;
            return result;
        }
    };
};

fn testTokenize(source: [:0]const u8, expected_token_tags: []const Token.Tag) !void {
    var tokenizer = Token.Tokenizer.init(source);
    for (expected_token_tags) |expected_token_tag| {
        const token = tokenizer.next();
        try std.testing.expectEqual(expected_token_tag, token.tag);
    }
}

test "eof" {
    try testTokenize("", &.{.eof});
}

test "number literal" {
    try testTokenize("0", &.{.number_literal});
}
test "special symbols" {
    try testTokenize("{", &.{.l_brace});
    try testTokenize("}", &.{.r_brace});
}

test "keywords" {
    try testTokenize("object", &.{.keyword_object});
    try testTokenize("def", &.{.keyword_object});
}
