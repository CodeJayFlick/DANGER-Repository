class DetectedObjects:
    def __init__(self, names, probabilities, bounding_boxes):
        self.names = names
        self.probabilities = probabilities
        self.bounding_boxes = bounding_boxes


class BoundingBox:
    def __init__(self, x, y, w, h):
        self.x = x
        self.y = y
        self.w = w
        self.h = h

    def to_tuple(self):
        return (self.x, self.y, self.w, self.h)


def single_shot_detection_translator(threshold, classes, image_width=0, image_height=0):
    ret_names = []
    ret_probs = []
    ret_bbs = []

    for i in range(len(class_ids)):
        class_id = int(class_ids[i])
        probability = probabilities[i]
        if class_id >= 0 and probability > threshold:
            if class_id >= len(classes):
                raise AssertionError("Unexpected index: " + str(class_id))
            className = classes[class_id]
            box = bounding_boxes[i].tolist()
            x = image_width * box[0] / (box[2] - box[0]) if image_width else box[0]
            y = image_height * box[1] / (box[3] - box[1]) if image_height else box[1]
            w = abs(image_width) * (box[2] - box[0]) / (box[2] - box[0]) if image_width else box[2] - x
            h = abs(image_height) * (box[3] - box[1]) / (box[3] - box[1]) if image_height else box[3] - y

            rect = Rectangle(x, y, w, h)
            ret_names.append(className)
            ret_probs.append(probability)
            ret_bbs.append(rect)

    return DetectedObjects(ret_names, ret_probs, [bb.to_tuple() for bb in ret_bbs])


class SingleShotDetectionTranslator:
    def __init__(self):
        pass

    def process_output(self, ctx, list):
        class_ids = list[0].numpy()
        probabilities = list[1].numpy()
        bounding_boxes = list[2]

        return single_shot_detection_translator(0.5, ["class_name"], image_width=1024, image_height=768)


def main():
    translator = SingleShotDetectionTranslator()
    output = translator.process_output(None, [[], [], []])
    print(output.names)
    print(output.probabilities)
    for bb in output.bounding_boxes:
        print(bb)


if __name__ == "__main__":
    main()

