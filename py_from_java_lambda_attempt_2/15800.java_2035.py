Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ai_djl.repository import Repository, Criteria, ZooModel
from ai_djl.modality.cv import Image
from ai_djl.modality.classification import Classifications
from ai_djl.exception import MalformedModelException, ModelNotFoundException

class TestDjlRepository(unittest.TestCase):

    def test_resource(self):
        repo = Repository.new_instance("DJL", "djl://ai.djl.mxnet/mlp")
        self.assertEqual(len(repo.get_resources()), 1)

        repo = Repository.new_instance("DJL", "djl://ai.djl.mxnet/resnet/0.0.1")
        self.assertEqual(len(repo.get_resources()), 1)

        repo = Repository.new_instance("DJL", "djl://ai.djl.mxnet/resnet/0.0.1/resnet18_v1")
        self.assertEqual(len(repo.get_resources()), 1)

        repo = Repository.new_instance("DJL", "djl://ai.djl(mxnet/fake/0.0.1")
        self.assertEqual(len(repo.get_resources()), 0)

        repo = Repository.new_instance("DJL", "djl//ai.djl(fake/mlp/0.0.1")
        self.assertEqual(len(repo.get_resources()), 0)

    def test_expect_throws(self):
        with self.assertRaises(IllegalArgumentException):
            Repository.new_instance("DJL", "djl://")

        with self.assertRaises(IllegalArgumentException):
            Repository.new_instance("DJL", "djl//ai.djl.mxnet")

        with self.assertRaises(IllegalArgumentException):
            Repository.new_instance("DJL", "djl//ai.djl(mxnet/")

    def test_zoo_model(self):
        criteria = Criteria.builder() \
                         .set_types(Image, Classifications) \
                         .opt_model_urls(["djl://ai.djl.mxnet/resnet/0.0.1/resnet18_v1"]) \
                         .build()
        
        try:
            model = criteria.load_model()
            self.assertEqual(model.name(), "resnet18_v1")
        except (MalformedModelException, ModelNotFoundException):
            pass

if __name__ == '__main__':
    unittest.main()
```

Note: This Python code uses the `unittest` module for testing and assumes that you have a similar Java class structure in your Python project.