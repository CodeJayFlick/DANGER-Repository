Here is the translation of the Java interface `ClipboardService` to a Python class:

```python
class ClipboardService:
    def register_clipboard_content_provider(self, service):
        pass

    def deregister_clipboard_content_provider(self, service):
        pass
```

Note that in Python, we don't have an explicit `public` keyword like Java does. Instead, we use the convention of prefixing method names with underscores to indicate they are intended for internal use only (e.g., `_register_clipboard_content_provider`). However, since this is a translation and not a rewrite, I've kept the original method names as they were in the Java interface.

Also, Python doesn't have an equivalent concept to Java's `interface`, so we're using a class with no implementation (i.e., all methods are defined but do nothing) to represent the interface.