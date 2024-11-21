import requests
from PIL import Image
import numpy as np
from paddlepaddle import PaddlePredictor

class OCRTest:
    def test_ocr(self):
        url = "https://resources.djl.ai/images/flight_ticket.jpg"
        img = self.load_image(url)
        boxes = self.detect_words(img)

        for box in boxes:
            sub_img = self.get_subimage(img, box['bounding_box'])
            if sub_img.height / sub_img.width > 1.5:
                sub_img = self.rotate_img(sub_img)
            result = self.predict_rotate_classifer(sub_img).best()
            if "Rotate" == result.class_name and result.probability > 0.8:
                sub_img = self.rotate_img(sub_img)
            name = self.recognize_text(sub_img)
            print(name)

    def detect_words(self, img):
        criteria = Criteria(Image(), DetectedObjects())
        criteria.set_types(Image(), DetectedObjects())
        criteria.opt_artifact_id("ai.djl.paddlepaddle:word_detection")
        criteria.opt_filter("flavor", "mobile")

        try:
            model = criteria.load_model()
            predictor = model.new_predictor()
            return predictor.predict(img)
        except Exception as e:
            print(f"Error occurred while detecting words: {e}")

    def get_recognizer(self):
        criteria = Criteria(Image(), str())
        criteria.set_types(Image(), str())
        criteria.opt_artifact_id("ai.djl.paddlepaddle:word_recognition")
        criteria.opt_filter("flavor", "mobile")

        try:
            model = criteria.load_model()
            predictor = model.new_predictor()
            return predictor
        except Exception as e:
            print(f"Error occurred while loading recognizer: {e}")

    def get_rotate_classifer(self):
        criteria = Criteria(Image(), Classifications())
        criteria.set_types(Image(), Classifications())
        criteria.opt_artifact_id("ai.djl.paddlepaddle:word_rotation")
        criteria.opt_filter("flavor", "mobile")

        try:
            model = criteria.load_model()
            predictor = model.new_predictor()
            return predictor
        except Exception as e:
            print(f"Error occurred while loading rotate classifer: {e}")

    def rotate_img(self, img):
        rotated = np.rot90(np.array(img), 1)
        return Image.fromarray(rotated)

    def get_subimage(self, img, box):
        rect = box['bounds']
        extended = self.extend_rect(rect[0], rect[1], rect[2], rect[3])
        width, height = img.size
        recovered = [(int)(extended[0] * width), (int)(extended[1] * height),
                     (int)(extended[2] * width), (int)(extended[3] * height)]
        return img.crop((recovered[0], recovered[1], recovered[2], recovered[3]))

    def extend_rect(self, xmin, ymin, width, height):
        centerx = xmin + width / 2
        centery = ymin + height / 2

        if width > height:
            width += height * 2.0
            height *= 3.0
        else:
            height += width * 2.0
            width *= 3.0

        new_x = centerx - width / 2 < 0 and 0 or centerx - width / 2
        new_y = centery - height / 2 < 0 and 0 or centery - height / 2
        new_width = new_x + width > 1 and 1 - new_x or width
        new_height = new_y + height > 1 and 1 - new_y or height

        return [new_x, new_y, new_width, new_height]

    def load_image(self, url):
        response = requests.get(url)
        img = Image.open(BytesIO(response.content))
        return img

    def predict_rotate_classifer(self, img):
        predictor = self.get_rotate_classifer()
        return predictor.predict(img)

    def recognize_text(self, img):
        predictor = self.get_recognizer()
        return predictor.predict(img).best().class_name
