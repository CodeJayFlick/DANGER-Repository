Here is the translation of the given Java code into Python:

```Python
class YoloV5Translator:
    def __init__(self):
        self.yolo_output_layer_type = None
        self.nms_threshold = 0.4

    @staticmethod
    def builder():
        return YoloV5Translator.Builder()

    @staticmethod
    def builder_with_args(arguments):
        yolo_v5_translator_builder = YoloV5Translator.builder()
        yolo_v5_translator_builder.config_pre_process(arguments)
        yolo_v5_translator_builder.config_post_process(arguments)
        return yolo_v5_translator_builder

    def box_intersection(self, a: Rectangle, b: Rectangle):
        w = self.overlap((a.x + a.width / 2), a.width, (b.x + b.width / 2), b.width) * 2
        h = self.overlap((a.y + a.height / 2), a.height, (b.y + b.height / 2), b.height) * 2
        if w < 0 or h < 0:
            return 0
        return w * h

    def box_iou(self, a: Rectangle, b: Rectangle):
        return self.box_intersection(a, b) / self.box_union(a, b)

    def box_union(self, a: Rectangle, b: Rectangle):
        i = self.box_intersection(a, b)
        return (a.width * a.height) + (b.width * b.height) - i

    def nms(self, list_of_intermediate_results):
        ret_classes = []
        ret_probs = []
        ret_bb = []

        for k in range(len(classes)):
            # 1. find max confidence per class
            pq = PriorityQueue()
            for intermediate_result in list_of_intermediate_results:
                if intermediate_result.detected_class == k:
                    pq.put(intermediate_result)

            while pq.qsize() > 0:
                # insert detection with max confidence
                detections = [pq.get()]
                rec = detections[0].location
                ret_classes.append(detections[0].id)
                ret_probs.append(detections[0].confidence)
                ret_bb.append(Rectangle(rec.x, rec.y, rec.width, rec.height))
                pq.clear()
                for j in range(1, len(detections)):
                    detection = detections[j]
                    location = detection.location
                    if self.box_iou(rec, location) < self.nms_threshold:
                        pq.put(detection)

        return DetectedObjects(ret_classes, ret_probs, ret_bb)

    def overlap(self, x1: float, w1: float, x2: float, w2: float):
        l1 = x1 - w1 / 2
        l2 = x2 - w2 / 2
        left = max(l1, l2)
        r1 = x1 + w1 / 2
        r2 = x2 + w2 / 2
        right = min(r1, r2)
        return right - left

    def process_from_box_output(self, list_of_nd_lists):
        flattened_list = [item for sublist in list_of_nd_lists[0] for item in sublist]
        intermediate_results = []
        size_classes = len(classes)
        stride = 5 + size_classes
        size = len(flattened_list) // stride
        for i in range(size):
            index_base = i * stride
            max_class = 0
            max_index = 0
            for c in range(size_classes):
                if flattened_list[index_base + c + 5] > max_class:
                    max_class = flattened_list[index_base + c + 5]
                    max_index = c

            score = max_class * flattened_list[index_base + 4]
            if score > threshold:
                x_pos = flattened_list[index_base]
                y_pos = flattened_list[index_base + 1]
                w = flattened_list[index_base + 2]
                h = flattened_list[index_base + 3]
                rect = Rectangle(max(0, x_pos - w / 2), max(0, y_pos - h / 2), w, h)
                intermediate_results.append(
                    IntermediateResult(classes[max_index], score, max_index, rect))

        return self.nms(intermediate_results)

    def process_from_detect_output(self):
        raise NotImplementedError("detect layer output is not supported yet")

    def process_output(self, ctx: TranslatorContext, list_of_nd_lists):
        if self.yolo_output_layer_type == YoloOutputType.DETECT:
            return self.process_from_detect_output()
        elif self.yolo_output_layer_type == YoloOutputType.AUTO:
            if len(list_of_nd_lists[0].shape) > 2:
                return self.process_from_detect_output()
            else:
                return self.process_from_box_output(list_of_nd_lists)
        else:  # YoloOutputType.BOX
            return self.process_from_box_output(list_of_nd_lists)

class Rectangle:
    def __init__(self, x: float, y: float, width: float, height: float):
        self.x = x
        self.y = y
        self.width = width
        self.height = height

class IntermediateResult:
    def __init__(self, id: str, confidence: double, detected_class: int, location: Rectangle):
        self.id = id
        self.confidence = confidence
        self.detected_class = detected_class
        self.location = location

class DetectedObjects:
    def __init__(self, ret_classes: list, ret_probs: list, ret_bb: list):
        self.ret_classes = ret_classes
        self.ret_probs = ret_probs
        self.ret_bb = ret_bb

class YoloOutputType(Enum):
    BOX = 1
    DETECT = 2
    AUTO = 3

class Builder:
    def __init__(self):
        self.output_type = YoloOutputType.AUTO
        self.nms_threshold = 0.4

    def opt_output_type(self, output_type: YoloOutputType) -> 'Builder':
        self.output_type = output_type
        return self

    def opt_nms_threshold(self, nms_threshold: float) -> 'Builder':
        self.nms_threshold = nms_threshold
        return self

    def config_post_process(self, arguments):
        super().config_post_process(arguments)
        type = ArgumentsUtil.value_string(arguments, "outputType", "AUTO")
        output_type = YoloOutputType.valueOf(type.upper(Locale.English))
        self.output_type = output_type
        nms_threshold = ArgumentsUtil.float_value(arguments, "nmsThreshold", 0.4)

    def build(self):
        # custom pipeline to match default YoloV5 input layer
        if not hasattr(self, 'pipeline'):
            add_transform(
                array -> array.transpose(2, 0, 1).to_type(DataType.FLOAT32, False) / 255)
        validate()
        return YoloV5Translator(self)

class TranslatorContext:
    pass

threshold = 0.4
classes = ["Class1", "Class2"]
```

Please note that this translation is not a direct copy-paste from Java to Python but rather an attempt to translate the code into equivalent Python syntax, considering the differences between both languages and their respective libraries.