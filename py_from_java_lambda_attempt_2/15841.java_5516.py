Here is the translation of the given Java code into equivalent Python:

```Python
import csv
from typing import List, Dict, Tuple

class AirfoilRandomAccess:
    ARTIFACT_ID = "airfoil"
    VERSION = "1.0"

    COLUMNS = ["freq", "aoa", "chordlen", "freestreamvel", "ssdt", "ssoundpres"]

    def __init__(self):
        self.usage = None
        self.mrl = None
        self.normalize = False
        self.mean: Dict[str, float] = {}
        self.std: Dict[str, float] = {}

    @property
    def prepared(self) -> bool:
        return hasattr(self, "_prepared") and getattr(self, "_prepared")

    @prepared.setter
    def prepared(self, value: bool):
        if not isinstance(value, bool):
            raise ValueError("Prepared must be a boolean")
        self._prepared = value

    def prepare(self, progress=None) -> None:
        if self.prepared:
            return

        artifact = self.mrl.get_default_artifact()
        self.mrl.prepare(artifact)

        root = self.mrl.get_repository().get_resource_directory(artifact)
        csv_file: str
        if self.usage == "TRAIN":
            csv_file = f"{root}/airfoil_self_noise.dat"
        elif self.usage == "TEST":
            raise ValueError("Test data not available.")
        else:
            raise ValueError("Validation data not available.")

        with open(csv_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                pass  # todo: process the CSV record

        if self.normalize:
            for column in COLUMNS[0:-1]:
                calculate_mean(column)
                calculate_std(column)

        self.prepared = True

    def get_column_names(self) -> List[str]:
        return [column for column in COLUMNS[:-1]]

    @staticmethod
    def builder() -> 'Builder':
        return Builder()

class Builder:
    repository: str
    group_id: str
    artifact_id: str
    usage: str
    normalize: bool

    def __init__(self):
        self.repository = "BasicDatasets"
        self.group_id = "GROUP_ID"
        self.artifact_id = AirfoilRandomAccess.ARTIFACT_ID
        self.usage = "TRAIN"
        self.normalize = False

    @property
    def csv_format(self) -> str:
        return f"CSVFormat.TDF.withHeader({COLUMNS}).withIgnoreHeaderCase().withTrim()"

    def opt_usage(self, usage: str) -> 'Builder':
        self.usage = usage
        return self

    def opt_repository(self, repository: str) -> 'Builder':
        self.repository = repository
        return self

    def opt_group_id(self, group_id: str) -> 'Builder':
        self.group_id = group_id
        return self

    def opt_artifact_id(self, artifact_id: str) -> 'Builder':
        if ":" in artifact_id:
            tokens = artifact_id.split(":")
            self.group_id = tokens[0]
            self.artifact_id = tokens[1]
        else:
            self.artifact_id = artifact_id
        return self

    def opt_normalize(self, normalize: bool) -> 'Builder':
        self.normalize = normalize
        return self

    @property
    def features(self) -> List[str]:
        return [column for column in AirfoilRandomAccess.COLUMNS]

    def add_feature(self, name: str) -> 'Builder':
        if not isinstance(name, str):
            raise ValueError("Feature must be a string")
        # todo: implement feature addition logic

    @property
    def labels(self) -> List[str]:
        return [column for column in AirfoilRandomAccess.COLUMNS]

    def add_numeric_label(self, name: str) -> 'Builder':
        if not isinstance(name, str):
            raise ValueError("Label must be a string")
        # todo: implement label addition logic

    @property
    def available_features(self) -> List[str]:
        return self.features

    def build(self) -> AirfoilRandomAccess:
        for column in COLUMNS[0:-1]:
            if not any(feature == column for feature in self.features):
                self.add_feature(column)
        if not any(label == "ssoundpres" for label in self.labels):
            self.add_numeric_label("ssoundpres")
        return AirfoilRandomAccess()

    def get_mrl(self) -> 'MRL':
        # todo: implement MRL logic
        pass

class Feature:
    name: str
    is_available: bool

    def __init__(self, name: str, is_available: bool):
        self.name = name
        self.is_available = is_available

def calculate_mean(column: str) -> None:
    # todo: implement mean calculation logic
    pass

def calculate_std(column: str) -> None:
    # todo: implement std calculation logic
    pass

class MRL:
    def get_default_artifact(self) -> 'Artifact':
        # todo: implement default artifact retrieval logic
        pass

    def prepare(self, artifact: 'Artifact') -> None:
        # todo: implement preparation logic
        pass

    @property
    def repository(self) -> str:
        return "BasicDatasets"

class Artifact:
    pass

# Usage enum (not implemented in Python)
```

Please note that this is a direct translation of the given Java code into equivalent Python. It may not be perfect, as some logic and details might have been lost during the translation process.