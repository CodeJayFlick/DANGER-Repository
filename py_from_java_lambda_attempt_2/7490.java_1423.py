Here is the equivalent Python code:

```Python
class FGEdgePaintTransformer:
    def __init__(self, options):
        self.options = options

    def apply(self, e):
        flow_type = e.get_flow_type()
        color = self.options.get_color(flow_type)
        return color
```

Note that I've used the following Python equivalents:

- `package` and `import` statements are not needed in Python as it uses a different approach to manage modules.
- The Java classes (e.g., `Function`, `Paint`) have been replaced with their equivalent Python concepts (`function`, `color`).
- The `@Override` annotation is not necessary in Python, as there's no need for explicit method overriding.