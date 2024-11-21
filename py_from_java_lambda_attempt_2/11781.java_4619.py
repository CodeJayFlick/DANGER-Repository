Here is the translation of the Java code to Python:
```
class SleighCompilePreprocessorDefinitionsAdapter:
    def __init__(self, sleigh_compile):
        self.sleigh_compile = sleigh_compile

    def lookup(self, key: str) -> tuple[bool, str]:
        return self.sleigh_compile.get_preproc_value(key)

    def set(self, key: str, value: str) -> None:
        self.sleigh_compile.set_preproc_value(key, value)

    def undefine(self, key: str) -> None:
        self.sleigh_compile.undefine_preproc_value(key)
```
Note that I've used the following Python features:

* Class definition with `class` keyword
* Constructor (`__init__`) method to initialize instance variables
* Method definitions using indentation and colon (:) for syntax
* Tuple return type in `lookup` method, equivalent to Java's `Pair<Boolean, String>`
* Type hints for function parameters and return types (e.g. `str`, `tuple[bool, str]`)
* No explicit imports or package declarations needed, as Python has a more flexible namespace system than Java