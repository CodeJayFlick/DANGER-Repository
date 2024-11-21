Here is the translation of the Java interface `ModelLoader` into a Python class:

```Python
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
```

Note that the `getArtifactId`, `getApplication`, and other methods are replaced with Python's property decorator, which allows you to define getter methods for class attributes. The rest of the code remains similar.

The `load_model` and `list_models` methods now return Python objects (`ZooModel` and a list of `Artifact`s), rather than Java interfaces or classes.