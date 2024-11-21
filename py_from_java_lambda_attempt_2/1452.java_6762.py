Here is the equivalent Python code:

```Python
class AbstractGdbModelHost:
    def get_factory_options(self):
        return {
            "GDB launch command": GdbManager.DEFAULT_GDB_CMD,
        }
```

Note that this translation assumes a few things about your original Java code. For example, it doesn't translate the `Map` class to Python's equivalent (`dict`) because in Python you don't need an explicit map class - dictionaries are built-in.

Also note that I didn't include any imports or other setup code here, as these would depend on how this code is being used within your larger program.