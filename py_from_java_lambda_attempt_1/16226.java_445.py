Here is the translation of the given Java code into equivalent Python:

```Python
import os

class TextClassificationModelLoader:
    APPLICATION = "nlp_text_classification"
    GROUP_ID = FtModelZoo.GROUP_ID  # Assuming this variable exists elsewhere in your codebase.
    ARTIFACT_ID = "cooking_stackexchange"
    VERSION = "0.0.1"

    def __init__(self, repository):
        pass

    def load_model(self, criteria):
        if not hasattr(criteria, 'get_filters'):
            raise ModelNotFoundException("No matching filter found")

        artifact = self.match_criteria(criteria.get_filters())
        progress = criteria.get_progress()

        if progress is not None:
            progress.reset("Loading", 2)
            progress.update(1)

        model_name = criteria.model_name
        if model_name is None:
            model_name = artifact.name

        model = FtModel(model_name)
        model_path = os.path.join(repository.resource_directory, artifact)
        model.load(model_path, model_name, criteria.options)
        return ZooModel(model, None)


class ModelNotFoundException(Exception):
    pass


class MalformedModelException(Exception):
    pass
```

Please note that this is a direct translation of the given Java code into Python. It does not include any error handling or validation checks which might be necessary for your specific use case.

Also, I have assumed that `FtModelZoo`, `Repository`, and other classes are defined elsewhere in your codebase. If they're not, you'll need to define them as well.