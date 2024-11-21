Here is the translation of the Java code into Python:

```Python
class GoToExternalLocationAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Go To External Location", plugin.name)

    @property
    def popup_menu_data(self):
        return MenuData(["Go to External Location"], "images/searchm_obj.gif", "0External")

    def is_enabled_for_context(self, context):
        if len(context.symbols) != 1:
            return False

        symbol = next(iter(context.symbols), None)
        if symbol is None or (symbol.symbol_type in [SymbolType.LABEL, SymbolType.FUNCTION] and not symbol.is_external()):
            return False
        return True

    def perform_action(self, context):
        symbol = next(iter(context.symbols), None)
        if symbol is None:
            return  # assume symbol removed

        obj = symbol.object
        ext_loc = None
        if isinstance(obj, Function) and obj.is_external():
            ext_loc = obj.external_location
        elif isinstance(obj, ExternalLocation):
            ext_loc = obj

        if ext_loc is not None:
            self.plugin.go_to(ext_loc)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of a class extending another. The equivalent code in Python would be to define classes and functions within modules, with no explicit inheritance between them.

Also note that I've used some liberties when translating the original code into Python:

- In the constructor (`__init__`) method, we don't have direct access to `super`'s methods like Java does. Instead, you can use a class's parent class (in this case, an abstract base class) and call its methods.
- The equivalent of Java's `@Override` annotation is not present in Python; however, it serves the same purpose: indicating that a method overrides one from its superclass.
- In Python, we don't have direct access to variables like `context.getSymbolCount()` or `symbol.getSymbolType()`. Instead, you can use list comprehensions (`len(context.symbols)`) and conditional statements (like `if isinstance(obj, Function)`).
- The equivalent of Java's `setPopupMenuData` method is not present in Python; however, we can achieve the same effect by defining a property for this class that returns an instance of our custom menu data.
- In Python, you don't need to explicitly check if an object is null before using it. Instead, you can use conditional statements (like `if symbol is None`) or try-except blocks (not shown here) to handle such cases.

This code should be a good starting point for your translation from Java to Python!