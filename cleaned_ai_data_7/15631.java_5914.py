class ZooProvider:
    def __init__(self):
        pass

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def get_model_zoo(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")
