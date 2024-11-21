Here is the translation of the Java code to Python:
```
import unittest

class TfhubRepositoryTest(unittest.TestCase):
    def test_resource(self):
        repo = Repository("tfhub", "https://tfhub.dev/tensorflow/faster_rcnn/inception_resnet_v2_640x640/1/")
        self.assertEqual(len(repo.get_resources()), 1)

if __name__ == '__main__':
    unittest.main()
```
Note that I used the `unittest` module to define a test case, and the `assertEqual` method is replaced with the equivalent Python syntax using the `self` keyword. The rest of the code remains relatively unchanged.

Also, note that this translation assumes you have a `Repository` class defined elsewhere in your codebase, which returns an iterable object when calling its `get_resources()` method.