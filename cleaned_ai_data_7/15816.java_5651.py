import os
from typing import List, Tuple, Optional

class BananaDetection:
    def __init__(self):
        self.usage = None
        self.image_paths: List[str] = []
        self.labels: List[Tuple[int, tuple]] = []

    @property
    def mrl(self) -> str:
        return "banana"

    @property
    def prepared(self) -> bool:
        return False

    def get_objects(self, index: int) -> Tuple[Optional[int], Optional[tuple]]:
        if self.labels and 0 <= index < len(self.labels):
            return (self.labels[index][0], self.labels[index][1])
        else:
            return None

    @property
    def available_size(self) -> int:
        return len(self.image_paths)

    def prepare(self, progress: Optional[int] = None) -> None:
        if not self.prepared:
            artifact_id = "banana"
            root_path = os.path.join("train", "index.file")
            try:
                with open(root_path, 'r') as f:
                    metadata = json.load(f)
                for entry in metadata.items():
                    img_name = entry[0]
                    image_paths.append(os.path.join(img_name))
                    label = list(map(float, entry[1]))
                    object_class = int(label[0])
                    x, y, w, h = map(int, label[1:])
                    self.labels.append((object_class, (x, y, w, h)))
            finally:
                self.prepared = True

    def get_image(self, index: int) -> Optional[str]:
        return f"image_paths[{index}]"

    @property
    def image_width(self) -> Optional[int]:
        return 256

    @property
    def image_height(self) -> Optional[int]:
        return 256


class Builder:
    def __init__(self):
        self.usage = Usage.TRAIN
        self.repository = "BasicDatasets. REPOSITORY"
        self.group_id = " BasicDatasets.GROUP_ID"
        self.artifact_id = "ARTIFACT_ID"

    @property
    def pipeline(self) -> Optional[str]:
        return None

    def opt_usage(self, usage: Usage) -> 'Builder':
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

    def build(self) -> BananaDetection:
        pipeline = Pipeline(ToTensor())
        return BananaDetection()
