import unittest
from ai_djl_examples_inference import ActionRecognition

class TestActionRecognition(unittest.TestCase):
    def test_action_recognition(self):
        try:
            result = ActionRecognition.predict()
            best = result.best
            self.assertEqual(best.class_name, "ThrowDiscus")
            self.assertTrue(abs(best.probability - 0.9) < 1e-6)
        except (ModelException, TranslateException, IOException) as e:
            raise

if __name__ == '__main__':
    unittest.main()
