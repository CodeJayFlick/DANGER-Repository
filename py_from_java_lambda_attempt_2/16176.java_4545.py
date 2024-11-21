Here is the translation of the Java code to Python:
```python
import unittest
from ai_djl_translate import ModelException, TranslateException, IOException
from typing import List

class ObjectDetectionWithTensorflowSavedModelTest(unittest.TestCase):
    def test_object_detection(self) -> None:
        if bool(os.environ.get("nightly")):  # Only run nightly, this example download the synset file from github, this can cause throttling and will fail the test.
            result = ObjectDetectionWithTensorflowSavedModel.predict()
            if result is None:
                raise SkipException("Only works for TensorFlow engine.")
        
        self.assertEqual(result.get_number_of_objects(), 3)
        objects: List[str] = ["dog", "bicycle", "car"]
        for obj in result.items():
            self.assertIn(obj.class_name, objects)
            self.assertGreaterEqual(obj.probability, 0.7)

if __name__ == "__main__":
    unittest.main()
```
Note that I've used the `unittest` framework to write a test case, and replaced Java-specific constructs like annotations (`@Test`) with Python's built-in support for testing (e.g., using the `assertEqual` method). Additionally, I've assumed that the `ObjectDetectionWithTensorflowSavedModel` class is defined elsewhere in your codebase.