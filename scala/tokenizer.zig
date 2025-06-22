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
        .{ "def", .keyword_def },
    });

    pub fn getKeyword(bytes: []const u8) ?Tag {
        return keywords.get(bytes);
    }

    pub const Tag = enum {
        invalid,
        number_literal,
        identifier,
        string_literal,
        eof,
        equal,
        l_paren,
        r_paren,
        l_brace,
        r_brace,
        l_bracket,
        r_bracket,
        colon,
        keyword_object,
        keyword_def,

        pub fn lexeme(tag: Tag) ?[]const u8 {
            return switch (tag) {
                .invalid,
                .string_literal,
                .number_literal,
                .eof,
                => null,

                .equal => "\"",
                .l_paren => "(",
                .r_paren => ")",
                .l_brace => "{",
                .r_brace => "}",
                .l_bracket => "[",
                .r_bracket => "]",

                .keyword_object => "object",
                .keyword_def => "object",
            };
        }
    };
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
        string_literal,
        string_literal_backslash,
        equal,
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
                ' ', '\n', '\t', '\r' => {
                    self.index += 1;
                    result.loc.start = self.index;
                    continue :state .start;
                },
                '"' => {
                    result.tag = .string_literal;
                    continue :state .string_literal;
                },
                '=' => continue :state .equal,
                '(' => {
                    result.tag = .l_paren;
                    self.index += 1;
                },
                ')' => {
                    result.tag = .r_paren;
                    self.index += 1;
                },
                '[' => {
                    result.tag = .l_bracket;
                    self.index += 1;
                },
                ']' => {
                    result.tag = .r_bracket;
                    self.index += 1;
                },
                '{' => {
                    result.tag = .l_brace;
                    self.index += 1;
                },
                '}' => {
                    result.tag = .r_brace;
                    self.index += 1;
                },
                ':' => {
                    result.tag = .colon;
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
            .string_literal => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index != self.buffer.len) {
                            continue :state .invalid;
                        } else {
                            result.tag = .invalid;
                        }
                    },
                    '\n' => result.tag = .invalid,
                    '\\' => continue :state .string_literal_backslash,
                    '"' => self.index += 1,
                    0x01...0x09, 0x0b...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => continue :state .string_literal,
                }
            },
            .string_literal_backslash => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0, '\n' => result.tag = .invalid,
                    else => continue :state .string_literal,
                }
            },
            .equal => {
                self.index += 1;
                result.tag = .equal;
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

fn testTokenize(source: [:0]const u8, expected_token_tags: []const Token.Tag) !void {
    var tokenizer = Tokenizer.init(source);
    for (expected_token_tags) |expected_token_tag| {
        const token = tokenizer.next();
        try std.testing.expectEqual(expected_token_tag, token.tag);
    }

    //try std.testing.expectEqual(expected_token_tags.len, i);

    //if (expected_token_tags.len != i) {
    //return std.testing.fail("Expected more tokens");
    //}
}

test "eof" {
    try testTokenize("", &.{.eof});
}

test "ignore spaces" {
    try testTokenize(" ", &.{.eof});
    try testTokenize("\n", &.{.eof});
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
    try testTokenize("def", &.{.keyword_def});
}

test "string literal" {
    try testTokenize("\"test\" 123 { } ", &.{
        .string_literal,
        .number_literal,
        .l_brace,
        .r_brace,
        .eof,
    });
}

test "empty object" {
    try testTokenize("object Main { }", &.{
        .keyword_object,
        .identifier,
        .l_brace,
        .r_brace,
        .eof,
    });
}

test "simple method" {
    try testTokenize("def main(args: Array[String]): Unit = { }", &.{
        .keyword_def,
        .identifier,
        .l_paren,
        .identifier,
        .colon,
        .identifier,
        .l_bracket,
        .identifier,
        .r_bracket,
        .r_paren,
        .colon,
        .identifier,
        .equal,
        .l_brace,
        .r_brace,
    });
}

test "simple method call" {
    try testTokenize("println(\"Hello World!\")", &.{
        .identifier,
        .l_paren,
        .string_literal,
        .r_paren,
    });
}

test "simple method definition with statement" {
    const str =
        \\def main(args: Array[String]): Unit = {
        \\  println("Hello World!")
        \\}
    ;

    try testTokenize(str, &.{
        .keyword_def,
        .identifier,
        .l_paren,
        .identifier,
        .colon,
        .identifier,
        .l_bracket,
        .identifier,
        .r_bracket,
        .r_paren,
        .colon,
        .identifier,
        .equal,
        .l_brace,

        .identifier,
        .l_paren,
        .string_literal,
        .r_paren,

        .r_brace,
        .eof,
    });
}

test "simple object definition with simple method and statement" {
    const str =
        \\object Main {
        \\  def main(args: Array[String]): Unit = {
        \\    println("Hello World!")
        \\  }
        \\}
    ;

    try testTokenize(str, &.{
        .keyword_object,
        .identifier,
        .l_brace,
        .keyword_def,
        .identifier,
        .l_paren,
        .identifier,
        .colon,
        .identifier,
        .l_bracket,
        .identifier,
        .r_bracket,
        .r_paren,
        .colon,
        .identifier,
        .equal,
        .l_brace,

        .identifier,
        .l_paren,
        .string_literal,
        .r_paren,

        .r_brace,
        .r_brace,
        .eof,
    });
}
