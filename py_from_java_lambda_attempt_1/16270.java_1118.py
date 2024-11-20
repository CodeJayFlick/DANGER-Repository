Here is the translation of the Java code to Python:

```Python
import os
from datetime import datetime
import unittest

class ModelZooTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # force downloading without cache in .djl.ai folder.
        if 'DJL_CACHE_DIR' not in os.environ:
            os.environ['DJL_CACHE_DIR'] = 'build/cache'
        user_home = os.path.expanduser('~')
        if 'ENGINE_CACHE_DIR' not in os.environ:
            os.environ['ENGINE_CACHE_DIR'] = f'{user_home}/.djl.ai'

    @classmethod
    def tearDownClass(cls):
        if 'DJL_CACHE_DIR' in os.environ:
            del os.environ['DJL_CACHE_DIR']
        if 'ENGINE_CACHE_DIR' in os.environ:
            del os.environ['ENGINE_CACHE_DIR']

    @unittest.skipIf(not datetime.today().weekday() == 5, "Weekly only")
    def test_download_models(self):
        for zoo in ModelZoo.list_model_zoo():
            for model_loader in zoo.get_model_loaders():
                artifacts = model_loader.list_models()
                for artifact in artifacts:
                    criteria = Criteria.builder() \
                        .set_types(NDList, NDList) \
                        .opt_filters(artifact.get_properties()) \
                        .build()
                    model = model_loader.load_model(criteria)
                    model.close()

    if __name__ == '__main__':
        unittest.main()
```

Please note that this translation is not perfect as Python does not have direct equivalent of Java's package, class and method. Also, the `@BeforeClass`, `@AfterClass` and `@Test` annotations are replaced with Python's built-in way to do setup/teardown and testing (using decorators).