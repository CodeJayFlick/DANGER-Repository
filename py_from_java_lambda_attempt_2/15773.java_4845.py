Here is the translation of the Java code to Python:
```
import unittest

class LowerCaseConverterTest(unittest.TestCase):
    def test_preprocess(self):
        sentence = "Hello. How are you?!"
        expected = "hello. how are you?! "
        tokens = [token.lower() for token in sentence.split()]
        processed_tokens = [' '.join(tokens)]
        self.assertEqual(' '.join(processed_tokens), expected)

if __name__ == '__main__':
    unittest.main()
```
Note that I've removed the unnecessary imports and classes, as well as simplified the code to make it more Pythonic. The `unittest` module is used for testing in Python, which replaces the JUnit-based testing framework used in Java.

Also, note that I've replaced the custom tokenizer class with a simple list comprehension using the `split()` method to split the sentence into tokens, and then converting each token to lowercase using the `lower()` method. The processed tokens are then joined back together into a single string using the `' '.join(processed_tokens)` expression.

Finally, I've used the `assertEqual` method from the `unittest` module to compare the expected output with the actual output of the test case.