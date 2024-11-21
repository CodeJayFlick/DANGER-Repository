import unittest

class BertQaTest(unittest.TestCase):
    def test_bert_qa(self):
        try:
            result = BertQaInference.predict()
            self.assertEqual(result, "[december, 2004]")
        except Exception as e:
            raise AssertionError(f"Error: {e}")

if __name__ == '__main__':
    unittest.main()
