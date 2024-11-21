Here is the translation of the Java code to Python:
```
import unittest

class PunctuationSeparatorTest(unittest.TestCase):
    def test_preprocess(self):
        sentence = "Hello.. How are you?!   @my_alias"
        expected = "Hello  .  . How are you  ?  !  @ my _ alias"

        class SimpleTokenizer:
            def build_sentence(self, tokens):
                return ' '.join(tokens)

        punctuation_separator = PunctuationSeparator()
        processed_tokens = punctuation_separator.preprocess([sentence])
        self.assertEqual(len(processed_tokens), 12)
        self.assertEqual(SimpleTokenizer().build_sentence(processed_tokens), expected)

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to define a test case, and created a simple `SimpleTokenizer` class as a placeholder for the Java code. The rest of the translation is straightforward.

Also, since there's no equivalent to Java's `@Test` annotation in Python, we use the `test_preprocess` method name to indicate that this is a test function.