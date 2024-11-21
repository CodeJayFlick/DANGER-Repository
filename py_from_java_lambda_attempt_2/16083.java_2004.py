Here is the equivalent Python code:

```Python
import tensorflow as tf
from PIL import Image
import numpy as np

class ResNetTest:
    def test_resnet50v1(self):
        criteria = {
            "application": "image_classification",
            "types": ["Image", "Classifications"],
            "artifact_id": "resnet",
            "filter": {"layers": 50, "flavor": "v1"}
        }

        file_path = "../../../examples/src/test/resources/kitten.jpg"
        img = Image.open(file_path)
        img_array = np.array(img)

        model = tf.keras.models.load_model("path_to_your_resnet_model")
        predictor = tf.keras.Sequential([model])

        result = predictor.predict(np.expand_dims(img_array, 0))
        print(result[0].numpy().argmax())
        assert result[0].numpy().argmax() == "n02124075 Egyptian cat"

# Usage
test = ResNetTest()
test.test_resnet50v1()

```

Please note that you need to replace `"path_to_your_resnet_model"` with the actual path to your trained ResNet model.