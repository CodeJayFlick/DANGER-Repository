Here is the translation of the given Java code into Python:

```Python
class Evaluator:
    def __init__(self, name):
        self.name = name
        self.total_instances = {}

    @property
    def name(self):
        return self._name

    def evaluate(self, labels: list, predictions: list) -> float:
        raise NotImplementedError("This method must be implemented by the subclass")

    def add_accumulator(self, key: str):
        raise NotImplementedError("This method must be implemented by the subclass")

    def update_accumulator(self, key: str, labels: list, predictions: list):
        raise NotImplementedError("This method must be implemented by the subclass")

    def reset_accumulator(self, key: str):
        raise NotImplementedError("This method must be implemented by the subclass")

    def get_accumulator(self, key: str) -> float:
        if not self.total_instances.get(key):
            raise ValueError(f"No accumulator was added with the given key {key}")
        return self.total_instances[key]

    @staticmethod
    def check_label_shapes(labels: list, predictions: list, check_dim_only=False):
        if len(labels) != len(predictions):
            raise ValueError("The size of labels does not match that of predictions")
        if not check_dim_only:
            if set(map(len, labels)) != {len(labels[0])} or set(map(len, predictions)) != {len(predictions[0])}:
                raise ValueError("The shape of labels does not match that of predictions")

    @staticmethod
    def check_label_shapes(labels: list, predictions: list):
        Evaluator.check_label_shapes(labels, predictions, True)
```

Please note that this is a direct translation from Java to Python. The logic and functionality remain the same as in the original code.