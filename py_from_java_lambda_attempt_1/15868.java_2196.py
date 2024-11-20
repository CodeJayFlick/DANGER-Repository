Here is the translation of the Java code to Python:
```python
import unittest
from ai_djl_basicdataset import TatoebaEnglishFrenchDataset, Configuration, NDManager, Record
from ai_djl_translate import TranslateException
try:
    from io import IOException
except ImportError:  # Python 3.x
    pass

class TatoebaEnglishFrenchDatasetTest(unittest.TestCase):
    EMBEDDING_SIZE = 15

    def test_get_data_with_pre_trained_embedding(self):
        with NDManager() as manager:
            tatoeba_english_french_dataset = TatoebaEnglishFrenchDataset.builder() \
                .set_source_configuration(Configuration(text_embedding=manager.get_text_embedding(EMBEDDING_SIZE))) \
                .set_target_configuration(Configuration(text_embedding=manager.get_text_embedding(EMBEDDING_SIZE))) \
                .set_sampling(32, True) \
                .opt_limit(10) \
                .build()
            tatoeba_english_french_dataset.prepare()
            record = tatoeba_english_french_dataset.get(manager, 0)
            self.assertEqual(record.data[0].shape.dimension(), 2)
            self.assertEqual(record.labels[0].shape.dimension(), 2)

    def test_get_data_with_trainable_embedding(self):
        with NDManager() as manager:
            tatoeba_english_french_dataset = TatoebaEnglishFrenchDataset.builder() \
                .set_source_configuration(Configuration(embedding_size=EMBEDDING_SIZE)) \
                .set_target_configuration(Configuration(embedding_size=EMBEDDING_SIZE)) \
                .set_sampling(32, True) \
                .opt_limit(10) \
                .build()
            tatoeba_english_french_dataset.prepare()
            record = tatoeba_english_french_dataset.get(manager, 0)
            self.assertEqual(len(record.data), 1)
            self.assertEqual(record.data[0].shape.dimension(), 1)
            self.assertEqual(len(record.labels), 1)
            self.assertEqual(record.labels[0].shape.dimension(), 1)

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to define a test class, and each method corresponds to one of the original Java tests. The code is written in Python 3.x syntax, but should be compatible with earlier versions as well.