Here is the translation of the Java code to Python:

```Python
import csv
from typing import Dict, Any

class AmazonReview:
    def __init__(self):
        self.mrl = None
        self.dataset_name = "us_Digital_Software"
        self.prepared = False

    @property
    def mrl(self) -> Any:
        return self._mrl

    @mrl.setter
    def mrl(self, value: Any) -> None:
        self._mrl = value

    @property
    def dataset_name(self) -> str:
        return self._dataset_name

    @dataset_name.setter
    def dataset_name(self, value: str) -> None:
        self._dataset_name = value

    @property
    def prepared(self) -> bool:
        return self._prepared

    @prepared.setter
    def prepared(self, value: bool) -> None:
        self._prepared = value

    def prepare(self):
        if not self.prepared:
            filter_ = {"dataset": self.dataset_name}
            artifact = self.mrl.match(filter_)
            self.mrl.prepare(artifact)
            csv_file_path = self.mrl.get_resource_directory(artifact).resolve(artifact.files.values().next().name)
            csv_url = str(csv_file_path) + "?"
            super().prepare()
            self.prepared = True

    @classmethod
    def builder(cls):
        return cls._Builder()

class _Builder:
    def __init__(self):
        self.repository = BasicDatasets.REPOSITORY
        self.group_id = "BasicDatasets.GROUP_ID"
        self.artifact_id = "amazon_reviews"
        self.dataset_name = "us_Digital_Software"

    @property
    def repository(self) -> Any:
        return self._repository

    @repository.setter
    def repository(self, value: Any) -> None:
        self._repository = value

    @property
    def group_id(self) -> str:
        return self._group_id

    @group_id.setter
    def group_id(self, value: str) -> None:
        self._group_id = value

    @property
    def artifact_id(self) -> str:
        return self._artifact_id

    @artifact_id.setter
    def artifact_id(self, value: str) -> None:
        if ":" in value:
            tokens = value.split(":")
            self.group_id = tokens[0]
            self.artifact_id = tokens[1]
        else:
            self.artifact_id = value

    @property
    def dataset_name(self) -> str:
        return self._dataset_name

    @dataset_name.setter
    def dataset_name(self, value: str) -> None:
        self._dataset_name = value

    def build(self):
        if not hasattr(self, "features") or len(getattr(self, "features")) == 0:
            raise ValueError("Missing features.")
        return AmazonReview()
```

Please note that Python does not have direct equivalent of Java's `CsvDataset` and other classes. Also, the code is simplified as much as possible to make it more readable in Python.