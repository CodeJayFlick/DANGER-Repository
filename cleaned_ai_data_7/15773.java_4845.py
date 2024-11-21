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
