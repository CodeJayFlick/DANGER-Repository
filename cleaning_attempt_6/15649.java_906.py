import numpy as np

class BoundingBoxError:
    def __init__(self, name):
        self.name = name
        self.ssd_box_prediction_error = {}

    def evaluate(self, labels, predictions):
        anchors = predictions[0]
        class_predictions = predictions[1].transpose(0, 2, 1)
        bounding_box_predictions = predictions[2]

        targets = multi_box_target.target([anchors, labels.head(), class_predictions])
        bounding_box_labels = targets[0]
        bounding_box_masks = targets[1]

        return np.abs((bounding_box_labels - bounding_box_predictions) * bounding_box_masks)

    def add_accumulator(self, key):
        self.ssd_box_prediction_error[key] = 0
        total_instances[key] = 0

    def update_accumulator(self, key, labels, predictions):
        error = self.evaluate(labels, predictions)
        update = np.sum(error).item()
        total_instances[key] += len(error)
        self.ssd_box_prediction_error[key] += update

    def reset_accumulator(self, key):
        total_instances[key] = 0
        self.ssd_box_prediction_error[key] = 0


def get_accumulator(self, key):
    if total_instances.get(key) == 0:
        return np.nan
    else:
        return self.ssd_box_prediction_error[key] / total_instances[key]


# Initialize the multi box target and total instances dictionaries
multi_box_target = {}
total_instances = {}

if __name__ == "__main__":
    # Example usage of BoundingBoxError class
    error_evaluator = BoundingBoxError("bounding_box_error")
    labels = [[1, 2], [3, 4]]
    predictions = [[[0.5, 0.6], [0.7, 0.8]], [[0.9, 0.1], [0.2, 0.3]]]
    
    error_evaluator.add_accumulator("key")
    error_evaluator.update_accumulator("key", labels, predictions)
    print(error_evaluator.get_accumulator("key"))
