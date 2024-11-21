Here is the translation of the Java interface `FilterDialogModel` to a Python class:

```python
class FilterDialogModel:
    def add_filter(self, filter):
        pass
    
    def force_refilter(self):
        pass
    
    def dialog_visibility_changed(self, is_visible: bool):
        pass
```

Note that in Python, we don't have an equivalent concept of interfaces like Java. Instead, we use abstract base classes (ABCs) or protocols to define a set of methods that must be implemented by any class that inherits from it.

In this case, I've simply defined a regular Python class `FilterDialogModel` with three methods: `add_filter`, `force_refilter`, and `dialog_visibility_changed`. The method signatures are similar to the Java interface, but without the type parameter `<T>` since Python is dynamically typed.