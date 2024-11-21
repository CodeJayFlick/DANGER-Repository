Here is the translation of the Java code to Python:

```Python
import os
from typing import List, Set

class TfLiteModelZoo:
    DJL_REPO_URL = "https://mlrepo.djl.ai/"
    REPOSITORY = None  # Initialize later
    GROUP_ID = "ai.djl.tflite"
    MODEL_LOADERS: List['BaseModelLoader'] = []

    def __init__(self):
        self.REPOSITORY = Repository(self.DJL_REPO_URL)
        mobilenet = self.REPOSITORY.model(CV.IMAGE_CLASSIFICATION, self.GROUP_ID, "mobilenet", "0.0.1")
        self.MODEL_LOADERS.append(BaseModelLoader(mobilenet))

    def get_model_loaders(self) -> List['BaseModelLoader']:
        return self.MODEL_LOADERS

    def get_group_id(self) -> str:
        return self.GROUP_ID

    def get_supported_engines(self) -> Set[str]:
        return {TfLiteEngine.ENGINE_NAME}

class Repository:
    pass  # Not implemented in this example, but you would need to implement the repository class here.

class BaseModelLoader:
    pass  # Not implemented in this example, but you would need to implement the base model loader class here.

class TfLiteEngine:
    ENGINE_NAME = "TfLite"

CV = None
MRL = None

# Initialize these later
os.environ['DJL_REPO_URL'] = 'https://mlrepo.djl.ai/'
```

Please note that this is a direct translation of Java code to Python, and you would need to implement the `Repository`, `BaseModelLoader` classes in your actual implementation.