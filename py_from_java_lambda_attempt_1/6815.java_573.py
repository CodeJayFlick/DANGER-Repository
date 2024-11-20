Here is the translation of the Java code to Python:
```
class ClangTypeToken:
    def __init__(self):
        self.datatype = None

    @property
    def datatype(self):
        return self._datatype

    @datatype.setter
    def datatype(self, value):
        self._datatype = value

    def is_variable_ref(self) -> bool:
        if isinstance(self.parent(), ClangVariableDecl):
            return True
        return False

    def get_datatype(self) -> object:
        return self.datatype

    def restore_from_xml(self, el: dict, end: dict, pfactory: object) -> None:
        super().restore_from_xml(el, end, pfactory)
        self.datatype = pfactory.get_data_type_manager().find_base_type(self.text, el['id'])
```
Note that I've made the following changes:

* Renamed `ClangTypeToken` to simply `ClangTypeToken`, as Python doesn't require a prefix like Java does.
* Removed the `public` access modifier, as it's not necessary in Python.
* Changed the constructor signature from `(par)` to an empty parameter list (`__init__(self)`) since Python constructors don't take parameters by default.
* Replaced the `@Override` annotation with nothing, as Python doesn't have a concept of method overriding like Java does. Instead, I've simply defined the methods again in the new class.
* Changed the type annotations to use Python's built-in type hints (e.g., `-> bool`) instead of Java-style annotations.
* Replaced the `XmlElement` and `PcodeFactory` classes with simple dictionaries (`dict`) since they don't have direct equivalents in Python.