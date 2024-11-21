import numpy as np

class AmazonReview:
    def __init__(self):
        self.marketplace = None
        self.star_rating = 0.0

    @classmethod
    def builder(cls):
        return cls()

    def prepare(self):
        pass

def test_amazon_reviews():
    dataset = AmazonReview.builder() \
                          .set_sampling(1, False) \
                          .add_categorical_feature("marketplace") \
                          .add_numeric_label("star_rating", 4.0) \
                          .opt_limit(2) \
                          .build()
    
    dataset.prepare()

    record = dataset.get(0)
    assert np.isclose(record[0], 0), "Expected marketplace value to be 0"
    assert np.isclose(record[1], 4.0), "Expected star rating to be 4.0"

if __name__ == "__main__":
    test_amazon_reviews()
