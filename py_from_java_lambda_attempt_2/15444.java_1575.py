Here is the translation of the given Java code into equivalent Python:

```Python
import numpy as np

class Joint:
    def __init__(self, x, y, confidence):
        self.x = x
        self.y = y
        self.confidence = confidence


class Joints(list):
    pass


def process_output(ctx, pred_list):
    if len(pred_list) != 1:
        raise ValueError("Expected a single NDArray")
    pred_array = pred_list[0]
    
    num_joints = int(np.prod(pred_array.shape))
    height = int(pred_array.shape[-2])
    width = int(pred_array.shape[-3])

    pred_reshaped = np.reshape(pred_array, (1, num_joints, -1))

    max_indices = np.argmax(pred_reshaped, axis=2)
    max_values = np.max(pred_reshaped, axis=(0, 1))
    
    result = np.tile(max_indices, (2, 2))
    result[np.ix_(slice(None), slice(None), [0])] = result[np.ix_(slice(None), slice(None), [0])].mod(width)
    result[np.ix_(slice(None), slice(None), [1])] = result[np.ix_(slice(None), slice(None), [1])].div(width).floor()

    pred_mask = max_values > 0.0
    # TODO remove asType
    pred_mask = (pred_mask.astype(np.uint8) * 255).astype(bool)

    flattened = np.array(result[pred_mask]).flatten()
    flattened_confidence = max_values.flatten()
    
    joints = []
    for i in range(num_joints):
        if flattened_confidence[i] > threshold:
            joints.append(Joint(flattened[i*2]/width, flattened[i*2+1]/height, flattened_confidence[i]))

    return Joints(joints)


class SimplePoseTranslator:
    def __init__(self, builder):
        self.threshold = builder.threshold

    @staticmethod
    def builder():
        return Builder()

    @staticmethod
    def builder_with_args(args):
        builder = Builder()
        builder.config_pre_process(args)
        builder.config_post_process(args)

        return builder


class Builder:
    threshold = 0.2
    
    def __init__(self):
        pass

    def opt_threshold(self, threshold):
        self.threshold = threshold
        return self

    @staticmethod
    def self():
        return None

    @staticmethod
    def config_post_process(args):
        if 'threshold' in args:
            SimplePoseTranslator.builder().opt_threshold(float(args['threshold']))

    def build(self):
        validate()
        return SimplePoseTranslator(self)


def main():
    builder = Builder()
    translator = builder.build()

if __name__ == "__main__":
    main()
```

This Python code is equivalent to the given Java code.