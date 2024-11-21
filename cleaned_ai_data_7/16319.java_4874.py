class BasicModelZoo:
    REPO_URL = "https://mlrepo.djl.ai/"
    repository = Repository("zoo", REPO_URL)
    GROUP_ID = "ai.djl.zoo"
    MODEL_LOADERS = []

    def __init__(self):
        self.mlp = self.repository.model(CV.IMAGE_CLASSIFICATION, self.GROUP_ID, "mlp", "0.0.3")
        self.MODEL_LOADERS.append(BaseModelLoader(self.mlp))

        self.resnet = self.repository.model(CV.IMAGE_CLASSIFICATION, self.GROUP_ID, "resnet", "0.0.2")
        self.MODEL_LOADERS.append(BaseModelLoader(self.resnet))

        self.ssd = self.repository.model(CV.OBJECT_DETECTION, self.GROUP_ID, "ssd", "0.0.2")
        self.MODEL_LOADERS.append(BaseModelLoader(self.ssd))

    def get_model_loaders(self):
        return self.MODEL_LOADERS

    def get_group_id(self):
        return self.GROUP_ID

    def get_supported_engines(self):
        supported_engines = set()
        supported_engines.add("MXNet")
        # TODO Currently WIP in supporting these two engines in the basic model zoo
        #         supported_engines.add("PyTorch")
        #         supported_engines.add("TensorFlow")
        return supported_engines

# Usage:
model_zoo = BasicModelZoo()
print(model_zoo.get_model_loaders())
print(model_zoo.get_group_id())
print(model_zoo.get_supported_engines())

