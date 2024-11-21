import numpy as np

class ObjectDetectionDataset:
    def __init__(self):
        pass

    def get(self, index: int) -> dict:
        data = self.get_record_image(index)
        objects = self.get_objects(index)

        labels_split = [[obj[0], obj[1].x, obj[1].y, obj[1].width, obj[1].height] for obj in objects]
        return {'data': np.array(data), 'labels': np.array(labels_split)}

    def get_record_image(self, index: int) -> list:
        # Implement this method to load the image data
        pass

    def get_objects(self, index: int) -> list:
        # Implement this abstract method in your subclass
        raise NotImplementedError("Must be implemented by a subclass")
