Here is the equivalent Python code:

```Python
class SQLParserException(Exception):
    def __init__(self, *args, **kwargs):
        if not args:
            super().__init__("Error format in SQL statement, please check whether SQL statement is correct.")
        elif len(args) == 1 and isinstance(args[0], str):
            super().__init__(args[0])
        else:
            super().__init__("Unsupported type: [{type}]. {message}".format(type=args[0], message=args[1]))
```

Note that Python does not have a direct equivalent to Java's `serialVersionUID`. The `__init__` method is used instead, which takes any number of positional and keyword arguments.