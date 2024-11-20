import os
from typing import List, Optional

class CocoDetection:
    def __init__(self):
        self.usage = None
        self.image_paths = []
        self.labels = []

    @classmethod
    def builder(cls) -> 'CocoDetection.Builder':
        return cls.Builder()

    def get_objects(self, index: int) -> List[tuple]:
        return self.labels[index]

    def prepare(self, progress=None):
        if not hasattr(self, 'prepared'):
            self.prepared = True

        mrl = Repository().dataset(Application.CV.ANY, BasicDatasets.GROUP_ID, CocoDetection.ARTIFACT_ID, CocoDetection.VERSION)
        artifact = mrl.get_default_artifact()
        root = os.path.join(mrl.get_repository().get_resource_directory(artifact))

        json_file = None
        if self.usage == 'TRAIN':
            json_file = os.path.join(root, "annotations", "instances_train2017.json")
        elif self.usage == 'TEST':
            json_file = os.path.join(root, "annotations", "instances_val2017.json")

        coco_utils = CocoUtils(json_file)
        coco_utils.prepare()
        image_ids = coco_utils.get_image_ids()

        for id in image_ids:
            path = os.path.join(coco_utils.get_relative_image_path(id))
            label_of_image_id = self.get_labels(coco_utils, id)

            if len(label_of_image_id) > 0:
                self.image_paths.append(path)
                self.labels.append(label_of_image_id)

    def get_labels(self, coco_utils: 'CocoUtils', image_id: int):
        annotation_ids = coco_utils.get_annotation_id_by_image_id(image_id)
        if annotation_ids is None:
            return []

        label = []
        for annotation_id in annotation_ids:
            annotation = coco_utils.get_annotationById(annotation_id)
            if annotation.get_area() > 0:
                box = annotation.get_bounding_box()
                label_class = coco_utils.map_category_id(annotation.get_category_id())
                object_location = Rectangle(Point(box[0], box[1]), box[2], box[3])
                label.append((label_class, object_location))

        return label

    def get_image(self, index: int):
        idx = index
        image_path = self.image_paths[idx]
        return ImageFactory().from_file(image_path)

    @property
    def available_size(self) -> int:
        return len(self.image_paths)


class CocoUtils:

    def __init__(self, json_file: str):
        pass

    def prepare(self):
        # todo implement this method
        pass


class Rectangle:
    def __init__(self, point: 'Point', width: float, height: float):
        self.point = point
        self.width = width
        self.height = height


class Point:
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y


CocoDetection.ARTIFACT_ID = "coco"
CocoDetection.VERSION = "1.0"


class Builder:
    def __init__(self):
        self.repository = BasicDatasets.REPOSITORY
        self.group_id = BasicDatasets.GROUP_ID
        self.artifact_id = CocoDetection.ARTIFACT_ID
        self.usage = 'TRAIN'
        self.flag = Image.Flag.COLOR

    @classmethod
    def builder(cls) -> 'Builder':
        return cls()

    def opt_usage(self, usage: str):
        self.usage = usage
        return self

    def opt_repository(self, repository: Repository):
        self.repository = repository
        return self

    def opt_group_id(self, group_id: str):
        self.group_id = group_id
        return self

    def opt_artifact_id(self, artifact_id: str):
        if ':' in artifact_id:
            tokens = artifact_id.split(':')
            self.group_id = tokens[0]
            self.artifact_id = tokens[1]
        else:
            self.artifact_id = artifact_id
        return self

    def build(self) -> 'CocoDetection':
        pipeline = Pipeline([ToTensor()])
        return CocoDetection(self)


class ImageFactory:

    @classmethod
    def from_file(cls, file_path: str):
        # todo implement this method
        pass


class Application:
    CV = "cv"


class BasicDatasets:
    GROUP_ID = "group_id"
    REPOSITORY = Repository()


class MRL:
    def __init__(self, repository: 'Repository'):
        self.repository = repository

    @classmethod
    def get_default_artifact(cls):
        # todo implement this method
        pass


class Pipeline:

    def __init__(self, transforms=None):
        if transforms is None:
            transforms = []
        self.transforms = transforms

    def add_transform(self, transform):
        self.transforms.append(transform)
