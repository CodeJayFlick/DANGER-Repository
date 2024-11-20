import paddle
from PIL import Image
import numpy as np

class PpWordRecognitionTranslator:
    def __init__(self):
        self.table = []

    def prepare(self, ctx):
        try:
            with open('rec_crnn/ppocr_keys_v1.txt', 'r') as f:
                self.table = [line.strip() for line in f.readlines()]
            self.table.insert(0, "blank")
            self.table.append("")
        except Exception as e:
            print(f"Error: {e}")

    def process_output(self, ctx, tokens):
        sb = StringBuilder()
        indices = np.argmax(tokens[0], axis=1).tolist()
        last_idx = 0
        for i in range(len(indices)):
            if indices[i] > 0 and not (i > 0 and indices[i] == last_idx):
                sb.append(self.table[int(indices[i])])
            last_idx = indices[i]
        return sb.toString()

    def process_input(self, ctx, input_image):
        img_array = np.array(input_image)
        hw = self.resize32(input_image.width)
        img_array = NDImageUtils.resize(img_array, (hw[1], hw[0]))
        img_array = (img_array - 0.5) / 0.5
        return [np.expand_dims(img_array, axis=0)]

    def resize32(self, w):
        width = max(32, int(w)) // 32 * 32
        return [32, width]

class StringBuilder:
    def __init__(self):
        self.sb = ""

    def append(self, s):
        self.sb += str(s)

    def toString(self):
        return self.sb

if __name__ == "__main__":
    translator = PpWordRecognitionTranslator()
    translator.prepare(None)
