Here is the translation of the Java code into Python:

```Python
import numpy as np

class DetectedObjects:
    def __init__(self, ret_names, ret_probs, ret_bb):
        self.ret_names = ret_names
        self.ret_probs = ret_probs
        self.ret_bb = ret_bb


class PtSsdTranslator:
    def __init__(self, builder):
        self.fig_size = builder.fig_size
        self.feat_size = builder.feat_size
        self.steps = builder.steps
        self.scale = builder.scale
        self.aspect_ratio = builder.aspect_ratio

    def prepare(self, ctx):
        manager = ctx.get_predictor_manager()
        self.box_recover = box_recover(manager, self.fig_size, self.feat_size, self.steps, self.scale, self.aspect_ratio)

    def process_output(self, ctx, list):
        scale_xy = 0.1
        scale_wh = 0.2

        # kill the 1st prediction as not needed
        prob = list[1].swapaxes(0, 1).softmax(axis=1)[:, 1:]
        prob = np.stack((prob.argmax(axis=1), prob.max(axis=(0, 1)))), dtype=np.float32)
        bounding_boxes = list[0].swapaxes(0, 1)

        bb_wh = bounding_boxes[:, :, 2:].mul(scale_wh).exp().mul(self.box_recover[:, 2:])
        bb_xy = (bounding_boxes[:, :, :2]).mul(scale_xy).mul(self.box_recover[:, 2:]).add(self.box_recover[:, :2])
        bounding_boxes = np.concatenate((bb_xy, bb_wh), axis=1)

        # filter the result below the threshold
        cut_off = prob[1].gte(threshold)
        bounding_boxes = bounding_boxes.transpose()[cut_off.astype(bool)].transpose()
        prob = prob.transpose()[cut_off.astype(bool)]

        # start categorical filtering
        order = prob[1].argsort().astype(int)
        desired_iou = 0.45

        ret_names, ret_probs, ret_bb = [], [], []
        recorder = {}

        for i in range(order.shape[0] - 1, -1, -1):
            curr_max_loc = order[i]
            class_prob = prob[curr_max_loc].astype(np.float32)
            class_id = int(class_prob[0])
            probability = class_prob[1]

            box_arr = bounding_boxes[curr_max_loc].astype(np.float32)

            rect = Rectangle(box_arr[0], box_arr[1], box_arr[2], box_arr[3])

            if class_id not in recorder:
                boxes = []
            else:
                boxes = recorder[class_id]
            below_iou = True
            for box in boxes:
                if box.iou(rect) > desired_iou:
                    below_iou = False
                    break

            if below_iou:
                boxes.append(rect)
                recorder.setdefault(class_id, []).append(rect)

        return DetectedObjects(ret_names, ret_probs, ret_bb)


def box_recover(manager, fig_size, feat_size, steps, scale, aspect_ratio):
    fk = manager.create(steps).astype(np.float64) / fig_size
    default_boxes = []

    for idx in range(feat_size.shape[0]):
        sk1 = scale[idx] * 1.0 / fig_size
        sk2 = scale[idx + 1] * 1.0 / fig_size
        sk3 = np.sqrt(sk1 * sk2)
        array = [np.array([sk1, sk1]), np.array([sk3, sk3])]

        for alpha in aspect_ratio[idx]:
            w = sk1 * np.sqrt(alpha)
            h = sk1 / np.sqrt(alpha)
            array.append(np.array([w, h]))
            array.append(np.array([h, w]))

        for size in array:
            for i in range(feat_size[idx]):
                for j in range(feat_size[idx]):
                    cx = (j + 0.5) / fk[idx]
                    cy = (i + 0.5) / fk[idx]
                    default_boxes.append(np.array([cx, cy] + size.tolist()))

    boxes = np.array(default_boxes).clip(0.0, 1.0)
    return manager.create(boxes)


class Builder:
    def __init__(self):
        self.fig_size = None
        self.feat_size = None
        self.steps = None
        self.scale = None
        self.aspect_ratio = None

    def set_boxes(self, fig_size, feat_size, steps, scale, aspect_ratio):
        self.fig_size = fig_size
        self.feat_size = feat_size
        self.steps = steps
        self.scale = scale
        self.aspect_ratio = aspect_ratio
        return self

    def build(self):
        validate()
        return PtSsdTranslator(self)


def main():
    builder = Builder().set_boxes(300, [38, 19, 10, 5, 3, 1], [8, 16, 32, 64, 100, 300],
                                   [21, 45, 99, 153, 207, 261, 315], [[2], [2, 3], [2, 3], [2, 3], [2], [2]])
    translator = builder.build()
    # Use the translator


if __name__ == "__main__":
    main()

class Rectangle:
    def __init__(self, x1, y1, x2, y2):
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2

    @property
    def iou(self, other):
        # Calculate IoU between two rectangles
        pass


threshold = 0.4
```

Please note that the `Rectangle` class and the `iou` method are not implemented in this translation as they were missing from your original Java code.