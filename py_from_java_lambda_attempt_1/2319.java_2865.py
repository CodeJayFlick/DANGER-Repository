Here is the equivalent Python code:

```Python
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
```

Note that Python does not have a direct equivalent to Java's `StreamTokenizer` class. Instead, we use the `re` module and regular expressions to tokenize the input string. The tokenization process is similar to what you would do manually: split the input into tokens based on whitespace characters or quoted strings.