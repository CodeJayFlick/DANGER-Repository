import unittest

class SimpleTokenizerTest(unittest.TestCase):
    def test_tokenize(self):
        sentence = "Hello! How are you?!"
        tokenizer = SimpleTokenizer()
        tokens = tokenizer.tokenize(sentence)
        expected_tokens = ["Hello!", "How", "are", "you?!"]
        self.assertEqual(len(tokens), len(expected_tokens))
        for i, token in enumerate(tokens):
            self.assertEqual(token, expected_tokens[i])
        self.assertEqual(tokenizer.build_sentence(tokens), sentence)

    def test_tokenize_with_single_word_token(self):
        sentence = "Hello"
        tokenizer = SimpleTokenizer()
        tokens = tokenizer.tokenize(sentence)
        expected_tokens = ["Hello"]
        self.assertEqual(len(tokens), len(expected_tokens))
        for i, token in enumerate(tokens):
            self.assertEqual(token, expected_tokens[i])
        self.assertEqual(tokenizer.build_sentence(tokens), sentence)

if __name__ == "__main__":
    unittest.main()
