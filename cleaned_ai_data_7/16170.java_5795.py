import os
from PIL import Image
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

class FeatureComparisonTest:
    def test_feature_comparison(self):
        if "pytorch" != Engine().get_engine_name():
            raise SkipException("Only works for PyTorch engine.")

        nightly = bool(os.environ.get('nightly', 'false'))
        if nightly:
            image_file1 = os.path.join('src/test/resources/', 'kana1.jpg')
            img1 = Image.open(image_file1)
            image_file2 = os.path.join('src/test/resources/', 'kana2.jpg')
            img2 = Image.open(image_file2)

            feature1 = FeatureExtraction().predict(img1)
            feature2 = FeatureExtraction().predict(img2)

            assert cosine_similarity([feature1], [feature2])[0][0] > 0.6

if __name__ == "__main__":
    test_feature_comparison()
