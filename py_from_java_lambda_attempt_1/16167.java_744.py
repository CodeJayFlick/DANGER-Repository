Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `unittest` module to define a test case class, and the `assertEqual` and `assertTrue` methods are equivalent to their Java counterparts. The `try-except` block is used to catch any exceptions raised by the `predict()` method.

Also, please note that this translation assumes that you have a Python package called `ai_djl_examples_inference` with an `ActionRecognition` class that has a `predict()` method and returns a result object with a `best` attribute. You may need to modify the code depending on your specific use case.