import numpy as np
from PIL import Image, ImageDraw

class BufferedImageWrapper:
    def __init__(self, image):
        self.image = image

    @property
    def width(self):
        return self.image.width

    @property
    def height(self):
        return self.image.height

    def get_subimage(self, x, y, w, h):
        new_image = Image.new('RGB', (w, h))
        draw = ImageDraw.Draw(new_image)
        draw.rectangle((0, 0) + (w-1, h-1), fill=self.image.getpixel((x,y)))
        return BufferedImageWrapper(new_image)

    def to_ndarray(self):
        width, height = self.image.size
        channel = 3 if self.image.mode == 'RGB' else 1

        data = np.array(list(self.image.getdata()))
        shape = (height, width) + (channel,)
        return data.reshape(shape).astype(np.uint8)

    def draw_bounding_boxes(self, detections):
        image_width, image_height = self.image.size
        for detection in detections:
            box = detection.bbox
            x1, y1, x2, y2 = map(lambda x: int(x * image_width), [box.xmin, box.ymin, box.xmax, box.ymax])
            draw.rectangle((x1, y1) + (x2-x1, y2-y1), fill=(random.randint(0,255), random.randint(0,255), random.randint(0,255)))

    def draw_joints(self, joints):
        for joint in joints:
            x, y = map(lambda x: int(x * image_width), [joint.x, joint.y])
            draw.ellipse((x-5, y-5) + (10, 10))

class BufferedImageFactory:
    @staticmethod
    def from_file(path):
        try:
            return BufferedImageWrapper(Image.open(str(path)))
        except IOError as e:
            raise e

    @staticmethod
    def from_url(url):
        try:
            return BufferedImageWrapper(Image.open(url))
        except IOError as e:
            raise e

    @staticmethod
    def from_image(image):
        if not isinstance(image, Image.Image):
            raise ValueError("only PIL image allowed")
        return BufferedImageWrapper(image)

    @staticmethod
    def to_ndarray(array):
        # implementation of NDArray.toNDArray()
        pass

    @staticmethod
    def save(image, os, type):
        try:
            image.save(os, type)
        except IOError as e:
            raise e

class DetectedObjects:
    class DetectedObject:
        def __init__(self, className, bbox):
            self.className = className
            self.bbox = bbox

def random_color():
    return (random.randint(0,255), random.randint(0,255), random.randint(0,255))

draw = ImageDraw.Draw(self.image)
