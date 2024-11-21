import numpy as np

class BigGANTranslator:
    def __init__(self, truncation):
        self.truncation = truncation

    def process_output(self, ctx, output_list):
        output_array = output_list[0] + 1 * 128 - 255.0
        sample_size = int(output_array.shape[0])
        images = [ImageFactory.getInstance().from_ndarray(output_array[i]) for i in range(sample_size)]
        return images

    def process_input(self, ctx, input):
        manager = ctx.get_nd_manager()
        classes = np.one_hot(input, 1000)
        seed = trunc_normal((input.shape[0], 128), truncation=self.truncation).astype(np.float32) * self.truncation
        return [manager.create(x) for x in (seed, classes, self.truncation)]

def truncated_normal(shape, truncation):
    mean = np.zeros_like(truncated_normal)
    std_dev = 1.0 / np.sqrt(2.0)
    return np.random.normal(mean, std_dev, shape).clip(-truncation, truncation)

class Image:
    def __init__(self, nd_array):
        self.nd_array = nd_array

ImageFactory = type('ImageFactory', (), {'getInstance': lambda: None})

def from_ndarray(nd_array):
    return Image(nd_array)
