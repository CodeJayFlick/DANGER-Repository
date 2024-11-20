import numpy as np
from PIL import Image

class SuperResolutionTranslator:
    def process_input(self, ctx, input):
        return [np.array(input).astype(np.float32)]

    def process_output(self, ctx, output_list):
        output = output_list[0].clip(0, 255)
        return Image.fromarray(output.astype('uint8'))
