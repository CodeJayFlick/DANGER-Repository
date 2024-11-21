Here is the translation of the given Java code into equivalent Python:

```Python
class Record:
    def __init__(self, data, label):
        self.data = data
        self.label = label


class ArrayDataset:
    def __init__(self, builder: 'ArrayDataset.Builder'):
        super().__init__()
        self.data = builder.data
        self.labels = builder.labels

        if len(self.data) == 0 or len(self.labels) != len(self.data):
            raise ValueError("All the NDArrays must have the same length!")

    def available_size(self):
        return self.data[0].size(0)

    def get(self, index: int):
        datum = []
        label = []
        for array in self.data:
            datum.append(array.get(index))
        if self.labels is not None:
            for array in self.labels:
                label.append(array.get(index))

        return Record(datum, label)


class ArrayDatasetBuilder:
    def __init__(self):
        self.data = []
        self.labels = []

    def set_data(self, *data: 'NDArray'):
        self.data = data
        return self

    def opt_labels(self, *labels: 'NDArray'):
        self.labels = labels
        return self

    def build(self) -> 'ArrayDataset':
        if len(self.data) == 0:
            raise ValueError("Please pass in at least one data")
        return ArrayDataset(self)
```

Note that this Python code does not include the NDArray class, as it is specific to Java. In a real-world scenario, you would need to implement your own equivalent of an NDArray class or use an existing library that provides similar functionality.

Also note that I've used type hints for clarity and readability purposes only.