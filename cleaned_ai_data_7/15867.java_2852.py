import unittest
from ai_djl_basicdataset import StanfordMovieReview
from ai_djl_ndarray import NDManager
from ai_djl_translate import TranslateException
from io import IOException


class TestStanfordMovieReview(unittest.TestCase):

    EMBEDDING_SIZE = 15

    def test_get_data_with_pre_trained_embedding(self):
        try:
            manager = NDManager.new_base_manager()
            dataset = StanfordMovieReview.builder() \
                .set_source_configuration(Configuration(text_embedding=manager.get_text_embedding(EMBEDDING_SIZE))) \
                .set_target_configuration(Configuration(text_embedding=manager.get_text_embedding(EMBEDDING_SIZE))) \
                .set_sampling(32, True) \
                .opt_limit(100) \
                .build()
            dataset.prepare()
            record = dataset.get(manager, 0)
            self.assertEqual(record.data[0].shape.dimension(), 2)
            self.assertEqual(record.labels[0].shape.dimension(), 0)

        except (IOException, TranslateException):
            pass

    def test_get_data_with_trainable_embedding(self):
        try:
            manager = NDManager.new_base_manager()
            dataset = StanfordMovieReview.builder() \
                .set_source_configuration(Configuration(text_embedding=manager.get_text_embedding(EMBEDDING_SIZE), embedding_size=EMBEDDING_SIZE)) \
                .set_target_configuration(Configuration(text_embedding=manager.get_text_embedding(EMBEDDING_SIZE), embedding_size=EMBEDDING_SIZE)) \
                .set_sampling(32, True) \
                .opt_limit(100) \
                .build()
            dataset.prepare()
            record = dataset.get(manager, 0)
            self.assertEqual(record.data[0].shape.dimension(), 2)
            self.assertEqual(record.labels[0].shape.dimension(), 0)

        except (IOException, TranslateException):
            pass


if __name__ == '__main__':
    unittest.main()
