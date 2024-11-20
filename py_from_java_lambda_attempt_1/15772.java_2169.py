Here is the equivalent Python code:

```Python
import unittest

class HyphenNormalizer:
    def preprocess(self, tokens):
        return ['-' * len(token) for token in tokens]

class TestHyphenNormalization(unittest.TestCase):

    def test_hyphen_normalization(self):
        hyphens1 = "-\u002D\u007E\u058A\u05BE\u2010\u2011\u2012\u2013\u2014\u2015\u2053"
        soft_hyphen = " Uni\u00adcode "
        hyphens2 = "\u207B\u208B\u2212\u2E3A\u2E3B\u301C\u3030\uFE31\uFE32\uFE58\uFE63\uFF0D"
        sentence = hyphens1 + soft_hyphen + hyphens2
        expected = "------------ Unicode ------------"

        tokenizer = SimpleTokenizer()
        tokens = tokenizer.tokenize(sentence)
        normalizer = HyphenNormalizer()
        processed_tokens = normalizer.preprocess(tokens)

        self.assertEqual(tokenizer.build_sentence(processed_tokens), expected)


if __name__ == '__main__':
    unittest.main()

class SimpleTokenizer:
    def tokenize(self, sentence):
        return [token for token in sentence.split()]

    def build_sentence(self, tokens):
        return ' '.join(tokens)
```

Please note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the built-in testing framework unittest and define test cases as methods of a class inheriting from `unittest.TestCase`.