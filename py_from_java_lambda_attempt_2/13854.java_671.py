Here is the translation of the Java code to Python:

```Python
class OrcOfficer:
    def __init__(self, handler):
        super().__init__(handler)

    def handle_request(self, req):
        if req.request_type == 'TORTURE_PRISONER':
            self.print_handling(req)
            req.mark_handled()
        else:
            super().handle_request(req)

    def __str__(self):
        return "Orc officer"
```

Note that Python does not have direct equivalents for Java's `package`, `public class`, and `@Override` annotations. The equivalent of a package in Python is the module, which can be imported using the `import` statement or created with the `__init__.py` file.

The `RequestHandler` class has been replaced by an abstract base class (ABC) called `super()` that provides default implementations for methods and attributes inherited from its parent.