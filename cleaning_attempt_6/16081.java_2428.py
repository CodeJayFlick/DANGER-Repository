import tensorflow as tf
from PIL import Image
import numpy as np

class MobileNetTest:
    def test_mobile_net_v2(self):
        # Load the model
        model = tf.keras.applications.MobileNetV2(weights='imagenet')

        # Load the image
        img_path = "../../../examples/src/test/resources/kitten.jpg"
        img = Image.open(img_path)

        # Preprocess the image
        img = np.array(img)
        img = tf.image.resize(img, (224, 224))
        img = img / 255.0

        # Make predictions with the model
        result = model.predict(np.expand_dims(img, axis=0))

        # Check if the prediction is correct
        assert result[0].argmax() == np.where(tf.string_split(["n02124075 Egyptian cat"])[1] == "Egyptian cat")[0][0]

if __name__ == "__main__":
    test = MobileNetTest()
    test.test_mobile_net_v2()
