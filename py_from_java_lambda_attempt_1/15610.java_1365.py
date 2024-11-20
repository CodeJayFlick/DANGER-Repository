Here is the translation of the Java code into Python:

```Python
class Metadata:
    def __init__(self):
        self.metadata_version = None
        self.resource_type = None
        self.application = None
        self.group_id = None
        self.artifact_id = None
        self.name = None
        self.description = None
        self.website = None
        self.licenses = {}
        self.artifacts = []
        self.last_updated = None

    def search(self, version_range: list, filter: dict) -> list:
        results = [artifact for artifact in self.artifacts if artifact.matches(version_range)]
        return [a for a in results if all(a.has_property(key, value) for key, value in filter.items())]

    @property
    def metadata_version(self):
        return self.metadata_version

    @metadata_version.setter
    def metadata_version(self, version: str):
        self.metadata_version = version

    # ... similar getters and setters for other attributes ...

    def get_application(self) -> 'Application':
        if not hasattr(self, '_application'):
            self._application = Application.of(self.application)
        return self._application

    @get_application.setter
    def application(self, app: str):
        self._application = app
        self.application_class = Application.of(app)

    # ... similar getters and setters for licenses, artifacts, last_updated ...

class MatchAllMetadata(Metadata):
    def __init__(self):
        super().__init__()
        self.group_id = DefaultModelZoo.GROUP_ID
        self.artifacts = []
        self.set_application(Application.UNDEFINED)
```

Note that Python does not have direct equivalents to Java's `transient` keyword or its `@Override` annotation. The equivalent of the latter is simply using a method with the same name and signature as the one being overridden.

Also, in Python, we use properties (getter/setter methods) instead of public fields for encapsulation.