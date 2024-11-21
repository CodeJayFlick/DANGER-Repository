import torch.nn as nn
from torchvision import models
from PIL import Image
import numpy as np
import os
import random
import copy

class ImageClassification:
    def __init__(self):
        pass

    @staticmethod
    def pretrained(input, classes, performance):
        if not isinstance(classes, str) or classes.lower() not in ['imagenet', 'digits']:
            raise ValueError("Unknown classes")

        model = None
        if classes == "Imagenet":
            require_mxnet()
            layers = performance.switch_performance('18', '50', '152')
            model = models.resnet(layers)
        elif classes == "Digits":
            require_basic()
            model = models.mlp()

        return ZooModel(model, translator)

    @staticmethod
    def train(dataset, performance):
        if not isinstance(dataset, ImageClassificationDataset) or not isinstance(performance, Performance):
            raise ValueError("Invalid dataset and/or performance")

        channels = dataset.get_image_channels()
        width = dataset.get_image_width().orElseThrow(lambda: ValueError("The dataset must have a fixed image width"))
        height = dataset.get_image_height().orElseThrow(lambda: ValueError("The dataset must have a fixed image height"))
        image_shape = (channels, height, width)
        classes = dataset.get_classes()

        train_dataset, validate_dataset = dataset.random_split(8, 2)

        num_layers = performance.switch_performance(18, 50, 152)
        block = ResNetV1.build(image_shape, num_layers, len(classes))
        model = Model("ImageClassification")
        model.set_block(block)

        training_config = DefaultTrainingConfig(loss=nn.CrossEntropyLoss())
        training_config.add_evaluator(Accuracy())
        training_config.add_training_listener(TrainingListener.Defaults.basic())

        try:
            trainer = model.new_trainer(training_config)
            trainer.initialize(np.ones((1,) + image_shape))
            EasyTrain.fit(trainer, 35, train_dataset, validate_dataset)
        except Exception as e:
            print(f"Error: {e}")

        translator = dataset.make_translator()
        return ZooModel(model, translator)

    @staticmethod
    def require_mxnet():
        pass

    @staticmethod
    def require_basic():
        pass


class Classes:
    IMAGENET = "Imagenet"
    DIGITS = "Digits"


class ImageClassificationDataset:
    def __init__(self):
        self.image_channels = None
        self.image_width = None
        self.image_height = None
        self.classes = []

    @staticmethod
    def random_split(ratio, num_classes):
        return train_dataset, validate_dataset

    @property
    def get_image_channels(self):
        return self.image_channels

    @get_image_channels.setter
    def set_image_channels(self, value):
        self.image_channels = value

    @property
    def get_image_width(self):
        return self.image_width

    @get_image_width.setter
    def set_image_width(self, value):
        self.image_width = value

    @property
    def get_image_height(self):
        return self.image_height

    @get_image_height.setter
    def set_image_height(self, value):
        self.image_height = value

    @property
    def get_classes(self):
        return self.classes

    @set_classes.setter
    def set_classes(self, value):
        self.classes = value


class ZooModel:
    def __init__(self, model, translator):
        self.model = model
        self.translator = translator


class Model:
    def __init__(self, name):
        self.name = name

    @staticmethod
    def new_instance(name):
        return Model(name)

    def set_block(self, block):
        pass


class Performance:
    def switch_performance(self, *args):
        if len(args) == 1:
            return args[0]
        elif len(args) > 2:
            raise ValueError("Invalid number of arguments")
        else:
            return random.choice(args)


def require_mxnet():
    pass

def require_basic():
    pass
