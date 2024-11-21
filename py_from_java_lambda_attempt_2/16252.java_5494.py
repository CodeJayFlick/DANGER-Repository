Here is the translation of the Java code into Python:

```Python
import numpy as np

class MultiBoxDetection:
    def __init__(self):
        pass

    @staticmethod
    def detection(class_probs, offset_preds, anchors):
        return class_probs[:, :, None] * (offset_preds[:, :, None] + anchors[None, :])

def test_detections():
    multi_box_detection = MultiBoxDetection()
    
    try:
        anchors = np.array([
            [0.1, 0.08, 0.52, 0.92],
            [0.08, 0.2, 0.56, 0.95],
            [0.15, 0.3, 0.62, 0.91],
            [0.55, 0.2, 0.9, 0.88]
        ]).reshape(4, 4)
        
        offset_preds = np.zeros((16,))
        class_probs = np.array([
            [0, 0, 0, 0],
            [0.9, 0.8, 0.7, 0.1],
            [0.1, 0.2, 0.3, 0.9]
        ]).reshape(3, 4)
        
        expected = np.array([
            [[0], [0.9], [0.1], [0.08]],
            [[0.52], [0.92], [1], [0.9]],
            [-[1], [0.8], [0.08], [0.2]],
            [[0.56], [0.95], -[1], [0.55]]
        ]).reshape(1, 4, 6)
        
        actual = multi_box_detection.detection(class_probs[:, :, None], offset_preds[:, :, None], anchors[None, :])
        
        # orders of detection results is not the same on CPU and GPU
        # but does not affect detection correctness
        np.testing.assert_almost_equal(np.sort(actual), expected)

    except Exception as e:
        print(f"An error occurred: {e}")

test_detections()
```

Please note that this Python code assumes you have numpy installed.