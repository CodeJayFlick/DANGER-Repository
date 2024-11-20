Here is the translation of the Java interface `TOCItemProvider` into a Python class:

```python
class TocItemProvider:
    def __init__(self):
        pass

    def get_external_toc_items_by_id(self) -> dict:
        """Returns all external TOC items referenced by this provider"""
        return {}

    def get_toc_definitions_by_id(self) -> dict:
        """Returns all TOC items defined by this provider"""
        return {}
```

Note that I've used the following Python concepts to translate the Java interface:

* `class` instead of `public class`
* No need for explicit method signatures (e.g., `public Map<...> getExternalTocItemsById()`)
* Dictionary types are represented using the built-in `dict` type
* Method return types and parameter lists are not explicitly declared, as Python does not require this

This translation maintains the same interface structure and functionality as the original Java code.