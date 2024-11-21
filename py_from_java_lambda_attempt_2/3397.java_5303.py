Here is the translation of the Java code to Python:
```
class AnalyzerEnablementState:
    def __init__(self, analyzer: object, enabled: bool, default_enabled: bool):
        self.name = analyzer.get_name()
        self.enabled = enabled
        self.default_enabled = default_enabled
        self.is_prototype = analyzer.is_prototype()

    @property
    def name(self) -> str:
        return self.name

    @property
    def is_enabled(self) -> bool:
        return self.enabled

    @property
    def is_default_enablement(self) -> bool:
        return self.enabled == self.default_enabled

    @property
    def is_prototype(self) -> bool:
        return self.is_prototype

    def set_enabled(self, enabled: bool):
        self.enabled = enabled
```
Note that I used the `@property` decorator to create read-only properties for the attributes. This is equivalent to Java's getter methods.

Also, I assumed that the `Analyzer` class has a method called `get_name()` and another method called `is_prototype()`. If these methods are not present in your Python code, you will need to modify them accordingly.

Finally, I used the `object` type for the `analyzer` parameter in the constructor, since it's equivalent to Java's `Analyzer` class.