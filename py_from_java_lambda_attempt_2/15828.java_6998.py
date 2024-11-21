Here is the translation of the Java code into Python:

```Python
import json
from pathlib import Path
from typing import List, Dict, Any

class CocoMetadata:
    def __init__(self):
        self.annotations = []
        self.images = []
        self.categories = []

class Annotation:
    def __init__(self, image_id: int, id: int):
        self.image_id = image_id
        self.id = id

class Image:
    def __init__(self, id: int, coco_url: str):
        self.id = id
        self.coco_url = coco_url

class CocoUtils:
    def __init__(self, annotation_path: Path):
        self.annotation_path = annotation_path
        self.prepared = False
        self.image_ids = []
        self.image_map = {}
        self.annotation_map = {}
        self.image_to_ann = {}
        self.category_id_map = {}

    def prepare(self) -> None:
        if not self.prepared:
            try:
                with open(str(self.annotation_path), 'r') as f:
                    metadata = json.load(f)
                self.create_index(metadata)
                self.prepared = True
            except Exception as e:
                print("Error: ", str(e))

    def create_index(self, metadata: Dict[str, Any]) -> None:
        for annotation in metadata['annotations']:
            image_id = int(annotation['image_id'])
            id = int(annotation['id'])
            if not self.image_to_ann.get(image_id):
                self.image_to_ann[image_id] = []
            self.image_to_ann[image_id].append(id)
            self.annotation_map[id] = Annotation(image_id, id)

        for image in metadata['images']:
            self.image_ids.append(int(image['id']))
            self.image_map[int(image['id'])] = Image(int(image['id']), image['coco_url'])

        category_ids = [int(category['id']) for category in metadata['categories']]
        for i, _ in enumerate(category_ids):
            self.category_id_map[category_ids[i]] = i
        self.image_ids.sort()

    def get_image_ids(self) -> List[int]:
        return self.image_ids

    def get_relative_image_path(self, image_id: int) -> Path:
        coco_url = self.image_map[image_id].coco_url.split('/')
        relative_path = Path(*[Path(c) for c in coco_url[-2:]])
        return relative_path

    def get_annotation_by_image_id(self, image_id: int) -> List[int]:
        return self.image_to_ann.get(image_id)

    def get_annotation_by_id(self, annotation_id: int) -> Annotation:
        return self.annotation_map[annotation_id]

    def map_category_id(self, original_category_id: int) -> int:
        return self.category_id_map[original_category_id]
```

Please note that Python does not have direct equivalent of Java's `HashMap` and other data structures. Instead, you can use built-in dictionaries or lists to achieve similar functionality.