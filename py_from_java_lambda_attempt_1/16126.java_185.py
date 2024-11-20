Here is the translation of the Java code to Python:

```Python
import logging
from ai_djl.translate import TranslateException
from ai_djl.repository.zoo import ZooModel
from ai_djl.modality.cv import Image
from ai_djl.inference.predictor import Predictor
from ai_djl.training.util.progress_bar import ProgressBar

class ActionRecognition:
    def __init__(self):
        pass

    @staticmethod
    def main():
        try:
            classification = ActionRecognition.predict()
            logging.info("{}", classification)
        except (IOException, ModelException, TranslateException) as e:
            print(f"An error occurred: {e}")

    @staticmethod
    def predict() -> dict:
        image_file_path = "src/test/resources/action_discus_throw.png"
        img = Image.from_file(image_file_path)

        criteria = {
            'application': 'CV.ACTION_RECOGNITION',
            'input_type': {'class_name': 'Image'},
            'output_type': {'class_name': 'Classifications'},
            'filter_backbone': 'inceptionv3',
            'filter_dataset': 'ucf101'
        }

        try:
            model = ZooModel.load(criteria)
            predictor = model.new_predictor()
            return predictor.predict(img)
        except (IOException, ModelException, TranslateException) as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    ActionRecognition.main()
```

Please note that this code is not a direct translation of the Java code. It's more like an equivalent Python implementation with some simplifications and assumptions made about how certain parts should be handled in Python.