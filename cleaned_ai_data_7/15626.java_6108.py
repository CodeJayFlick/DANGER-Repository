class ModelLoader:
    def __init__(self):
        pass

    @property
    def artifact_id(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def application(self) -> 'Application':
        raise NotImplementedError("Subclasses must implement this method")

    def load_model(self, criteria: 'Criteria') -> 'ZooModel':
        raise NotImplementedError("Subclasses must implement this method")

    def list_models(self) -> List['Artifact']:
        raise NotImplementedError("Subclasses must implement this method")
