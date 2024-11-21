import unittest
from ai_djl_translate import TranslateException
from io import IOException

class TrainSeq2SeqTest(unittest.TestCase):

    def test_train_seq2seq(self):
        args = ["-g", "1", "-e", "1", "-m", "2"]
        try:
            result = train_seq2seq.run_example(args)
            self.assertIsNotNone(result)
        except (IOException, TranslateException) as e:
            raise

if __name__ == '__main__':
    unittest.main()
