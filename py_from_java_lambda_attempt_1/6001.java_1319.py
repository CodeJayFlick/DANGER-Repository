Here's a translation of the Java code into equivalent Python:

```Python
class ProcessorProjectDataColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Processor"

    def get_value(self, info: dict, settings: dict, data: dict) -> str:
        if 'meta_data' in info and 'processor' in info['meta_data']:
            return info['meta_data']['processor']
        else:
            raise ValueError("Invalid metadata")

    @property
    def column_preferred_width(self):
        return 100

    @property
    def is_default_column(self) -> bool:
        return True

    @property
    def priority(self) -> int:
        return 1
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or some of the other constructs used in the original code. The above translation is a straightforward conversion into equivalent Python syntax and semantics.

In particular:

- In Python, we don't need to specify types explicitly like we do with Java.
- We use classes instead of packages for organizing our code.
- We can define properties (like `column_preferred_width`, `is_default_column` and `priority`) using the `@property` decorator in Python.