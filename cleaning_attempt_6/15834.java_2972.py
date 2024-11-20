import os
from typing import Iterable

class CookingStackExchange:
    ARTIFACT_ID = "cooking_stackexchange"
    VERSION = "1.0"

    def __init__(self, usage: str):
        self.usage = usage
        self.mrl = None
        self.prepared = False

    def get_data(self) -> str:
        if not self.prepared:
            self.prepare(None)
        return self.root

    def prepare(self, progress=None) -> None:
        if self.prepared:
            return
        artifact = self.get_mrl().get_default_artifact()
        self.mrl.prepare(artifact, progress)

        item = None
        usage_type = {"TRAIN": "train", "TEST": "test"}
        for key in usage_type.keys():
            if self.usage == key:
                item = artifact.get_files()[usage_type[key]]
                break

        if not item:
            raise ValueError("Only training and testing dataset supported.")

        self.root = os.path.abspath(self.mrl.get_repository().get_file(item, ""))
        self.prepared = True

    @classmethod
    def builder(cls):
        return cls.Builder()

class Builder:
    repository: str
    group_id: str
    artifact_id: str
    usage: str

    def __init__(self):
        self.repository = "BasicDatasets. REPOSITORY"
        self.group_id = "BasicDatasets.GROUP_ID"
        self.artifact_id = CookingStackExchange.ARTIFACT_ID
        self.usage = "TRAIN"

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

    def opt_usage(self, usage: str) -> 'Builder':
        self.usage = usage
        return self

    def build(self) -> CookingStackExchange:
        return CookingStackExchange(self.usage)

    def get_mrl(self) -> None:
        return Repository(dataset=NLP.ANY, group_id=self.group_id, artifact_id=self.artifact_id, version=CookingStackExchange.VERSION)
