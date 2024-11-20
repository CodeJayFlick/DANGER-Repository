import unittest
from transformers import UniversalSentenceEncoder

class TestUniversalSentenceEncoder(unittest.TestCase):

    def test_sentiment_analysis(self):
        if not "nightly":
            raise unittest.SkipTest("Nightly only")

        if Engine().get_engine_name() != "TensorFlow":
            raise unittest.SkipTest("Only works for TensorFlow engine.")

        inputs = ["The quick brown fox jumps over the lazy dog.", 
                  "I am a sentence for which I would like to get its embedding"]

        model = UniversalSentenceEncoder.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
        result = model.encode(inputs, return_tensors='pt', truncation=True)

        self.assertIsNotNone(result)
        
    def test_sentiment_analysis_again(self):
        if not "nightly":
            raise unittest.SkipTest("Nightly only")

        if Engine().get_engine_name() != "TensorFlow":
            raise unittest.SkipTest("Only works for TensorFlow engine.")

        inputs = ["The quick brown fox jumps over the lazy dog.", 
                  "I am a sentence for which I would like to get its embedding"]

        model = UniversalSentenceEncoder.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
        result = model.encode(inputs, return_tensors='pt', truncation=True)

        self.assertAlmostEqual(result[0][0], -0.031330183, places=4)


if __name__ == '__main__':
    unittest.main()
