import unittest
from ai_djl_translate import TrainCaptcha

class TestTrainCaptcha(unittest.TestCase):
    def test_train_captcha(self):
        args = ["-g", "1", "-e", "1", "-m", "2"]
        result = TrainCaptcha.run_example(args)
        self.assertIsNotNone(result)

if __name__ == '__main__':
    unittest.main()
