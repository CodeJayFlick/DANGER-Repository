import logging
from PIL import Image
import numpy as np
from ai_djl.translate.translate_exception import TranslateException
from ai_djl.translate.model_exception import ModelException
from ai_djl.translate.predictor import Predictor
from ai_djl.translate.zoo_model import ZooModel

# Set up the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class ObjectDetection:
    def __init__(self):
        pass

    @staticmethod
    def main():
        try:
            detection = ObjectDetection.predict()
            print(detection)
        except (IOException, ModelException, TranslateException) as e:
            logger.error("Error: %s", str(e))

    @staticmethod
    def predict():
        image_file_path = "src/test/resources/dog_bike_car.jpg"
        img = Image.open(image_file_path)

        backbone = ""
        if Engine.get_engine_name() == "TensorFlow":
            backbone = "mobilenet_v2"
        else:
            backbone = "resnet50"

        criteria = Criteria()
        criteria.set_application(Application.CV.OBJECT_DETECTION)
        criteria.set_types(Image, DetectedObjects)
        criteria.opt_filter("backbone", backbone)
        criteria.opt_progress(ProgressBar())

        try:
            model = ZooModel.load_model(criteria)
            predictor = model.new_predictor()

            detection = predictor.predict(img)

            ObjectDetection.save_bounding_box_image(img, detection)

            return detection
        except (IOException, ModelException) as e:
            logger.error("Error: %s", str(e))

    @staticmethod
    def save_bounding_box_image(img, detection):
        output_dir_path = "build/output"
        try:
            os.makedirs(output_dir_path)
        except OSError:
            pass

        new_img = img.copy()
        new_img.putalpha(255)  # Make image copy with alpha channel because original image was jpg
        new_img.draw_bounding_boxes(detection)

        output_file_path = f"{output_dir_path}/detected-dog_bike_car.png"
        new_img.save(output_file_path, "PNG")
        logger.info("Detected objects image has been saved in: %s", output_file_path)


if __name__ == "__main__":
    ObjectDetection.main()
