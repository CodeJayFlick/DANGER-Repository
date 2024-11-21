import unittest
from ai_djl_modality_nlp_embedding import TrainableWordEmbedding, DefaultVocabulary, SimpleTokenizer

class TestTrainableWordEmbedding(unittest.TestCase):

    TEST_STRING = "Deep Java Library (DJL) is an open-ource, high-level, engine-agnostic Java framework for deep learning. DJL is designed to be easy to get started with and simple to use for Java developers. DJL provides a native Java development experience and functions like any other regular Java library.\n" + \
                 "use for Java developers. DJL provides a native Java development experience and functions like any other regular Java library."

    UNKNOWN_TOKEN = "<unk>"

    def test_word_embedding(self):
        trainable_word_embedding = TrainableWordEmbedding.builder()\
            .set_vocabulary(DefaultVocabulary.builder().add(SimpleTokenizer().tokenize(TEST_STRING)).opt_max_tokens(10).opt_unknown_token(UNKNOWN_TOKEN).build())\
            .opt_use_default(True)\
            .build()

        with NDManager.new_base_manager():
            index = trainable_word_embedding.preprocess_word_to_embed("Java")
            word = trainable_word_embedding.unembed_word(index)
            self.assertEqual(word, "Java")

            index = trainable_word_embedding.preprocess_word_to_embed(UNKNOWN_TOKEN)
            word = trainable_word_embedding.unembed_word(index)
            self.assertEqual(word, UNKNOWN_TOKEN)

if __name__ == '__main__':
    unittest.main()
