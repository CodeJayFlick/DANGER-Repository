class DetectedObjects:
    def __init__(self, classes, probs, bb):
        self.classes = classes
        self.probs = probs
        self.bb = bb


class BoundingBox:
    def __init__(self, x_min, y_min, width, height):
        self.x_min = x_min
        self.y_min = y_min
        self.width = width
        self.height = height

    def to_dict(self):
        return {
            'x_min': self.x_min,
            'y_min': self.y_min,
            'width': self.width,
            'height': self.height
        }

class YoloTranslator:
    def __init__(self, builder):
        pass  # Not implemented in the original Java code

    @staticmethod
    def builder():
        return Builder()

    @staticmethod
    def builder_with_args(args):
        return Builder().config_pre_process(args).config_post_process(args)

    def process_output(self, ctx, list):
        class_indices = [int(x) for x in list[0].flatten()]
        probs = [float(x) for x in list[1].flatten()]
        bounding_boxes = list[2]
        detected = len(probs)

        x_min = (bounding_boxes[:, 0] / ctx['image_width']).clip(0, 1)
        y_min = (bounding_boxes[:, 1] / ctx['image_height']).clip(0, 1)
        x_max = (bounding_boxes[:, 2] / ctx['image_width']).clip(0, 1)
        y_max = (bounding_boxes[:, 3] / ctx['image_height']).clip(0, 1)

        box_x = [x for x in x_min]
        box_y = [y for y in y_min]
        box_width = [(x - y) for x, y in zip(x_max, x_min)]
        box_height = [(y - z) for x, y, z in zip(y_max, y_min, bounding_boxes[:, 3])]

        ret_classes = []
        ret_probs = []
        ret_bb = []

        for i in range(detected):
            if class_indices[i] < 0 or probs[i] < ctx['threshold']:
                continue
            ret_classes.append(ctx['classes'][class_indices[i]])
            ret_probs.append(probs[i])
            rect = {'x': box_x[i], 'y': box_y[i], 'width': box_width[i], 'height': box_height[i]}
            ret_bb.append(rect)

        return DetectedObjects(ret_classes, ret_probs, ret_bb)


class Builder:
    def __init__(self):
        pass  # Not implemented in the original Java code

    def config_pre_process(self, args):
        self.args = args
        return self

    def config_post_process(self, args):
        self.args = args
        return self

    def build(self):
        raise NotImplementedError('Method not implemented')
