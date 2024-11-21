import numpy as np
from typing import List

class MultiBoxPrior:
    def __init__(self, sizes: List[List[float]], ratios: List[List[float]]):
        self.sizes = sizes
        self.ratios = ratios


class SingleShotDetection:
    def __init__(self, builder: 'SingleShotDetection.Builder'):
        self.features = builder.features
        self.class_prediction_blocks = builder.class_prediction_blocks
        self.anchor_prediction_blocks = builder.anchor_prediction_blocks
        self.multi_box_priors = builder.multi_box_priors
        self.num_classes = builder.num_classes

    def forward_internal(self, parameter_store: dict, inputs: List[np.ndarray], training: bool) -> List[np.ndarray]:
        network_output = inputs[0]
        anchors_outputs = []
        class_outputs = []
        bounding_box_outputs = []

        for i in range(len(self.features)):
            network_output = self.features[i].forward(parameter_store, network_output, training)

            multi_box_prior = self.multi_box_priors[i]

            anchor_boxes = multi_box_prior.generate_anchor_boxes(network_output)
            anchors_outputs.append(anchor_boxes)

            class_predictions = self.class_prediction_blocks[i].forward(parameter_store, network_output, training)[0]
            class_outputs.append(class_predictions)

            bounding_box_predictions = self.anchor_prediction_blocks[i].forward(parameter_store, network_output, training)[0]
            bounding_box_outputs.append(bounding_box_predictions)

        anchors = np.concatenate(anchors_outputs)
        class_predictions = np.concatenate(class_outputs).reshape(-1, len(self.multi_box_priors), self.num_classes + 1)
        bounding_box_predictions = np.concatenate(bounding_box_outputs).reshape(-1, len(self.multi_box_priors))

        return [anchors, class_predictions, bounding_box_predictions]

    def concat_predictions(self, output: List[np.ndarray]) -> np.ndarray:
        flatten_output = []
        for array in output:
            transpose_array = np.transpose(array)
            reshape_array = transpose_array.reshape(transpose_array.shape[0], -1)
            flatten_output.append(reshape_array)

        return np.concatenate(flatten_output)


class SingleShotDetection.Builder:
    def __init__(self):
        self.features: List[type] = []
        self.sizes: List[List[float]] = []
        self.ratios: List[List[float]] = []
        self.num_classes: int = 0
        self.class_prediction_blocks: List[Block] = []
        self.anchor_prediction_blocks: List[Block] = []
        self.multi_box_priors: List[MultiBoxPrior] = []

    def set_sizes(self, sizes: List[List[float]]) -> 'SingleShotDetection.Builder':
        self.sizes = sizes
        return self

    def set_ratios(self, ratios: List[List[float]]) -> 'SingleShotDetection.Builder':
        self.ratios = ratios
        return self

    def set_num_classes(self, num_classes: int) -> 'SingleShotDetection.Builder':
        self.num_classes = num_classes
        return self

    def build(self) -> SingleShotDetection:
        if not self.features and len(self.sizes) == 0:
            raise ValueError("Either features or sizes must be set")

        for i in range(len(self.sizes)):
            size_list = [float(x) for x in self.sizes[i]]
            ratio_list = [float(x) for x in self.ratios[i]]

            num_anchors = len(size_list) + len(ratio_list) - 1
            class_prediction_block = getClassPredictionBlock(num_anchors, self.num_classes)
            anchor_prediction_block = getAnchorPredictionBlock(num_anchors)

            self.class_prediction_blocks.append(class_prediction_block)
            self.anchor_prediction_blocks.append(anchor_prediction_block)
            multi_box_prior = MultiBoxPrior(size_list, ratio_list)
            self.multi_box_priors.append(multi_box_prior)

        return SingleShotDetection(self)


def getClassPredictionBlock(numAnchors: int, numClasses: int) -> Block:
    # implement the logic to create a class prediction block
    pass


def getAnchorPredictionBlock(numAnchors: int) -> Block:
    # implement the logic to create an anchor prediction block
    pass

