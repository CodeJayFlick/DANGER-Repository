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
