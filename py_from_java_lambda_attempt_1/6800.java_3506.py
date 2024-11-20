Here is the translation of the Java code to Python:
```
class ClangBreak:
    def __init__(self, par):
        self.super(par)
        self.indent = 0

    def __init__(self, par, indent):
        self.super(par)
        self.indent = indent

    @property
    def indent(self):
        return self._indent

    def restore_from_xml(self, el, end, pfactory):
        super().restore_from_xml(el, end, pfactory)
        self._indent = int(el.get("indent"))
```
Note that I've used the following Python concepts to translate the Java code:

* Classes and objects: `ClangBreak` is a class with two constructors (`__init__`) and an attribute `indent`.
* Properties: The `@property` decorator allows us to define getter and setter methods for the `indent` attribute.
* Methods: I've translated each method from Java to Python, using the same names (e.g. `getIndent()` becomes a property named `indent`).