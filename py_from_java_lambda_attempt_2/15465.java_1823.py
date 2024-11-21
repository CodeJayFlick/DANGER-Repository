Here is the translation of the Java code into Python:

```Python
class WordpieceTokenizer:
    def __init__(self, vocabulary, unknown_token, max_input_chars):
        self.unknown = unknown_token
        self.max_input_chars = max_input_chars
        self.vocabulary = vocabulary

    def tokenize(self, sentence):
        output_tokens = []
        for token in super().tokenize(sentence.strip()):
            if len(token) > self.max_input_chars:
                output_tokens.append(self.unknown)
                continue
            
            is_bad = False
            subtokens = []
            current_substring = None
            while True:
                end = len(token)
                while start < end:
                    sb = StringBuilder()
                    sb.append(token, start, end)
                    if start > 0:
                        sb.insert(0, "##")
                    substring = str(sb)
                    if self.vocabulary.contains(substring):
                        current_substring = substring
                        break
                    else:
                        current_substring = None
                    end -= 1
                
                if current_substring is None:
                    is_bad = True
                    break
                subtokens.append(current_substring)
                if len(subtokens) > self.max_input_chars:
                    raise ValueError(f"Too many subTokens for: '{sentence}'")
                
                start = end
            
            if is_bad:
                output_tokens.append(self.unknown)
            else:
                output_tokens.extend(subtokens)
        
        return output_tokens
```

Note that Python does not have an exact equivalent to Java's `List` and `StringBuilder`. Instead, we use the built-in list type (`[]`) for lists and the `str.join()` method or a loop with concatenation for string manipulation.