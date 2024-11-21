Here's a translation of the Java code into equivalent Python:

```Python
class CodeViewerActionContext:
    def __init__(self, provider):
        super().__init__(provider, provider)

    def __init__(self, provider, location):
        super().__init__(provider, provider, location)

    @property
    def is_dynamic_listing(self):
        return (getattr(get_component_provider(), 'is_dynamic_listing')).__call__()
```

Note that Python does not have direct equivalent of Java's `public` and `private` access modifiers. In Python, everything is public by default.

Also note the use of property decorator (`@property`) to create a getter for the `is_dyanmic_listing` attribute. This allows you to call it like an attribute (e.g., `ctx.is_dynamic_listing`) rather than as a method (e.g., `ctx.is_dynamic_listing()`).