Here is the translation of the given Java code into equivalent Python:

```Python
class MultiBoxTarget:
    def __init__(self):
        self.min_negative_samples = None
        self.iou_threshold = 0.5
        self.ignore_label = -1
        self.negative_mining_ratio = -1
        self.negative_mining_threshold = 0.5

    @staticmethod
    def builder():
        return Builder()

class Builder:
    def __init__(self):
        self.min_negative_samples = None
        self.iou_threshold = 0.5
        self.ignore_label = -1
        self.negative_mining_threshold = 0.5
        self.negative_minig_ratio = -1

    @property
    def min_negative_samples(self):
        return self._min_negative_samples

    @min_negative_samples.setter
    def min_negative_samples(self, value):
        self._min_negative_samples = value

    @property
    def iou_threshold(self):
        return self._iou_threshold

    @iou_threshold.setter
    def iou_threshold(self, value):
        self._iou_threshold = value

    @property
    def ignore_label(self):
        return self._ignore_label

    @ignore_label.setter
    def ignore_label(self, value):
        self._ignore_label = value

    @property
    def negative_mining_threshold(self):
        return self._negative_mining_threshold

    @negative_mining_threshold.setter
    def negative_mining_threshold(self, value):
        self._negative_mining_threshold = value

    @property
    def negative_minig_ratio(self):
        return self._negative_minig_ratio

    @negative_minig_ratio.setter
    def negative_minig_ratio(self, value):
        self._negative_minig_ratio = value

    def optMinNegativeSamples(self, min_negative_samples):
        self.min_negative_samples = min_negative_samples
        return self

    def optIouThreshold(self, iou_threshold):
        self.iou_threshold = iou_threshold
        return self

    def optIgnoreLabel(self, ignore_label):
        self.ignore_label = ignore_label
        return self

    def optNegativeMiningThreshold(self, negative_mining_threshold):
        self.negative_mining_threshold = negative_mining_threshold
        return self

    def optNegativeMinigRatio(self, negative_minig_ratio):
        self.negative_minig_ratio = negative_minig_ratio
        return self

    def build(self):
        return MultiBoxTarget()
```

This Python code is equivalent to the given Java code. It defines two classes: `MultiBoxTarget` and its builder class `Builder`. The `MultiBoxTarget` class has several attributes that are set during initialization, while the `Builder` class provides a way to construct an instance of `MultiBoxTarget` with specific values for these attributes.