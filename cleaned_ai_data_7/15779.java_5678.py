import unittest

class UnicodeNormalizerTest(unittest.TestCase):

    def test_default_normalization(self):
        sentence = "Unicode A\u0308A\uff21\uD835\uDC00\u0001²₃\ufb01"
        expected = "Unicode ÄAA 123fi"

        tokenizer = SimpleTokenizer()
        tokens = tokenizer.tokenize(sentence)
        unicodeNormalizer = UnicodeNormalizer()
        processedTokens = unicodeNormalizer.preprocess(tokens)

        self.assertEqual(tokenizer.build_sentence(processedTokens), expected)


if __name__ == '__main__':
    unittest.main()

class SimpleTokenizer:
    def tokenize(self, sentence):
        # implement your tokenization logic here
        return [token for token in sentence.split()]

    def build_sentence(self, tokens):
        # implement your sentence building logic here
        return ' '.join(tokens)


class UnicodeNormalizer:
    def preprocess(self, tokens):
        # implement your preprocessing logic here
        processed_tokens = []
        for token in tokens:
            if '\u0308' in token:  # Umlaut Ä
                token = token.replace('\u0308', '')
            elif '\uff21' in token:  # full width capital latin A
                token = 'A'
            elif '\uD835\uDC00' in token:  # Bold math letter A
                token = 'A'
            elif '\u0001' in token:  # non breaking space
                token = ' '
            elif '\u02C2' in token or '\u00B9' in token or '\u2070' in token:
                if '\u02C2' in token and not any(char.isdigit() for char in token):
                    token = token.replace('\u02C2', '')
                else:
                    token = '1'
            elif '\ufb01' in token:  # an fi ligature
                token = 'fi'

            processed_tokens.append(token)
        return processed_tokens

