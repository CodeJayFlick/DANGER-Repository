Here is the translation of the Java code into Python:

```Python
class Batch:
    def __init__(self,
                 manager: 'NDManager',
                 data: 'NDList',
                 labels: 'NDList',
                 size: int,
                 data_batchifier: 'Batchifier',
                 label_batchifier: 'Batchifier',
                 progress: long,
                 progress_total: long):
        self.manager = manager
        self.data = data
        self.labels = labels
        self.size = size
        self.data_batchifier = data_batchifier
        self.label_batchifier = label_batchifier
        self.progress = progress
        self.progress_total = progress_total

    def get_manager(self) -> 'NDManager':
        return self.manager

    def get_data(self) -> 'NDList':
        return self.data

    def get_labels(self) -> 'NDList':
        return self.labels

    def get_size(self) -> int:
        return self.size

    def get_progress(self) -> long:
        return self.progress

    def get_progress_total(self) -> long:
        return self.progress_total

    def close(self):
        if hasattr(self.manager, "close"):
            self.manager.close()
        self.manager = None


def split(data: 'NDList', batchifier: 'Batchifier', device_count: int, even_split: bool) -> list['NDList']:
    if batchifier is None:
        raise ValueError("Split can only be called on a batch containing a batchifier")
    return batchifier.split(data, device_count, even_split)


class NDManager:
    def close(self):
        pass


class Batchifier:
    def split(self, data: 'NDList', num_of_slices: int, even_split: bool) -> list['NDList']:
        raise NotImplementedError("Batchifier must implement the split method")


# Example usage
manager = NDManager()
data = [1, 2, 3]
labels = ['a', 'b', 'c']
batch_size = len(data)
data_batchifier = Batchifier()
label_batchifier = Batchifier()

batch = Batch(manager, data, labels, batch_size, data_batchifier, label_batchifier, 0, 100)

device_count = 2
even_split = True

splitted_data = split(batch.get_data(), data_batchifier, device_count, even_split)
splitted_labels = split(batch.get_labels(), label_batchifier, device_count, even_split)

for i in range(device_count):
    print(f"Device {i}: Data - {splitted_data[i]}, Labels - {splitted_labels[i]}")
```

Please note that this translation is not perfect as Python does not support Java's `@Override` annotation or type hints for method return types. Also, the code assumes that you have implemented the necessary classes (`NDManager`, `Batchifier`) and methods in your Python program.