Here is the equivalent Python code:

```Python
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
```

Please note that this code is not a direct translation of the Java code, but rather an equivalent Python implementation. The original code seems to be part of a larger system and may require additional setup or dependencies to run correctly.

Here are some key differences between the two codes:

1. **Java vs Python**: This is the most obvious difference. Python has its own syntax, libraries, and frameworks that differ from Java's.
2. **Engine() method**: In the original code, `Engine().getInstance()` returns an instance of the engine. In this translation, I replaced it with a simple function call to mimic the behavior.
3. **FeatureExtraction class**: The original code has a `FeatureExtraction` class that is used to extract features from images. This translation assumes you have implemented such a class in Python and are using its predict method.
4. **Image processing library**: Java's image processing capabilities come with its standard libraries, while Python uses PIL (Python Imaging Library) for this purpose.

Remember that these changes were made based on my understanding of the original code. If there is any specific context or requirements you'd like me to consider when translating the code, please let me know!