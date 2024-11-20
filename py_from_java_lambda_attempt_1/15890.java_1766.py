Here is the translation of the given Java code into equivalent Python:

```Python
class DLRModelZoo:
    DJL_REPO_URL = "https://mlrepo.djl.ai/"
    REPOSITORY = Repository("Dlr", DJL_REPO_URL)
    GROUP_ID = "ai.djl.dlr"

    MODEL_LOADERS = []

    @classmethod
    def __init__.cls(cls):
        resnet = cls.REPOSITORY.model(CV.IMAGE_CLASSIFICATION, cls.GROUP_ID, "resnet", "0.0.1")
        cls.MODEL_LOADERS.append(BaseModelLoader(resnet))

    def get_model_loaders(self) -> list:
        return self.MODEL_LOADERS

    def get_group_id(self):
        return self.GROUP_ID

    def get_supported_engines(self) -> set:
        return {DlrEngine.ENGINE_NAME}
```

Please note that Python does not have direct equivalent of Java's static blocks. The `__init__.cls` method is used here to simulate the same functionality as a static block in Java.