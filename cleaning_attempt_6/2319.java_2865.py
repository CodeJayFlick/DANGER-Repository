import re

class StreamTokenizerExperiments:
    @staticmethod
    def tokenize(cmd_line):
        tokens = []
        tokenizer = re.compile(r'[^"\s]+|"[^"]*"|\s+')
        for token in tokenizer.finditer(cmd_line):
            if token.group() == ' "':
                continue
            elif token.group().startswith('"'):
                tokens.append(token.group()[1:-1])
            else:
                tokens.append(token.group())
        return tokens

    def test_stream_tokenizer_string(self):
        assert StreamTokenizerExperiments.tokenize("echo \"Hello, World!\"") == ["echo", "Hello, World!"]

    def test_stream_tokenizer_escaped_quote_in_string(self):
        assert StreamTokenizerExperiments.tokenize("echo \"Hello, \\\"World!\"\"") == ["echo", "Hello, \"World!\""]

    def test_stream_tokenizer_escaped_space(self):
        assert StreamTokenizerExperiments.tokenize("echo Hello,\\ World!") == ["echo", "Hello,\ World!"]
