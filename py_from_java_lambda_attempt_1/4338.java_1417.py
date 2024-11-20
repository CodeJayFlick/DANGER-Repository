Here is the translation of the Java code to Python:
```
class HasTranslationValueColumnConstraint:
    def accepts(self, value: str, context: dict) -> bool:
        return value.get_translated_value() is not None and len(value.get_translated_value()) > 0

    def get_name(self) -> str:
        return "Has Translated Value"

    def get_editor(self, column_data_source: list) -> object:
        from ghidra.app.plugin.core.strings import DoNothingColumnConstraintEditor
        return DoNothingColumnConstraintEditor(self)
```
Note that I've made the following assumptions:

* The `StringDataInstance` class is equivalent to a Python dictionary or string.
* The `TableFilterContext` and `ColumnData` classes are not used in this translation, so they have been removed.
* The `DoNothingColumnConstraintEditor` class is imported from the same package as before.

Also, I've kept the method names and variable names similar to the original Java code for clarity.