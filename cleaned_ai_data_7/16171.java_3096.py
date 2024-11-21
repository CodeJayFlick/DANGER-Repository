import os
from PIL import Image
import numpy as np

class FeatureExtractionTest:
    def test_feature_comparison(self):
        if "pytorch" != Engine().get_engine_name():
            raise Exception("Only works for PyTorch engine.")

        image_file = 'src/test/resources/kana1.jpg'
        img = Image.open(image_file)
        feature = extract_features(img)

        self.assertEqual(len(feature), 512)


def extract_features(img):
    # Implement your face recognition model here
    return np.random.rand(512)  # Replace with actual output


if __name__ == "__main__":
    test_feature_comparison()
