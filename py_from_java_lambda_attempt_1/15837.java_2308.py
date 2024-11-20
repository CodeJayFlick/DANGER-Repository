Here is the translation of the given Java code into Python:

```Python
class TatoebaEnglishFrenchDataset:
    def __init__(self):
        self.usage = None
        self.mrl = None
        self.prepared = False

    @property
    def usage(self):
        return self._usage

    @usage.setter
    def usage(self, value):
        self._usage = value

    @property
    def mrl(self):
        return self._mrl

    @mrl.setter
    def mrl(self, value):
        self._mrl = value

    def prepare(self, progress=None):
        if self.prepared:
            return

        artifact = self.mrl.get_default_artifact()
        self.mrl.prepare(artifact, progress)
        root = self.mrl.get_repository().get_resource_directory(artifact)

        usage_path = None
        if self.usage == 'TRAIN':
            usage_path = os.path.join(root, "fra-eng-train.txt")
        elif self.usage == 'TEST':
            usage_path = os.path.join(root, "fra-eng-test.txt")
        else:
            raise ValueError("Validation data not available.")

        source_text_data = []
        target_text_data = []

        with open(usage_path) as reader:
            for row in reader:
                text = row.strip().split("\t")
                source_text_data.append(text[0])
                target_text_data.append(text[1])

        self.preprocess(source_text_data, True)
        self.preprocess(target_text_data, False)

        self.prepared = True

    def get(self, manager=None, index=0):
        data = []
        labels = []

        for text in [source_text_data[index], target_text_data[index]]:
            # Assuming you have a function to convert the text into embeddings
            embedding = your_embedding_function(text)
            if not isinstance(embedding, list) or len(embedding) != 2:
                raise ValueError("Embeddings must be lists of length 2")
            data.append(list(map(float, embedding[0])))
            labels.append(list(map(float, embedding[1])))

        return {"data": np.array(data), "labels": np.array(labels)}

    def available_size(self):
        return len(source_text_data)

class Builder:
    def __init__(self):
        self.artifact_id = 'tatoeba-en-fr'
        self.usage = None
        self.mrl = None

    @property
    def usage(self):
        return self._usage

    @usage.setter
    def usage(self, value):
        self._usage = value

    @property
    def mrl(self):
        return self._mrl

    @mrl.setter
    def mrl(self, value):
        self._mrl = value

    def build(self):
        dataset = TatoebaEnglishFrenchDataset()
        dataset.usage = self.usage
        dataset.mrl = self.mrl
        return dataset

# Usage example:
builder = Builder()
dataset = builder.build()
dataset.prepare()

for i in range(dataset.available_size()):
    record = dataset.get(index=i)
    print(record["data"], record["labels"])
```

Please note that this is a direct translation of the Java code into Python. You may need to adjust it according to your specific requirements and the actual implementation details (e.g., `your_embedding_function`).