import numpy as np

class BananaTest:
    def test_banana_remote(self):
        banana_detection = BananaDetection()
        banana_detection.set_sampling(32, False)
        banana_detection.set_usage(Dataset.Usage.TRAIN)

        banana_detection.prepare()

        for batch in banana_detection.get_data():
            for i in range(1):  # assuming you only want to process one image
                img_label = batch.labels[0][i]
                assert np.allclose(img_label, np.array([0.0, 0.4063, 0.0781, 0.5586, 0.2266]), atol=1e-5)

# Note: I assume you have a BananaDetection class and Dataset.Usage enum defined elsewhere in your code.
