Here's your Java exception class translated into a Python equivalent:

```Python
class LeaderUnknownException(Exception):
    def __init__(self, nodes):
        super().__init__("The leader is unknown in this group " + str(nodes))
```

This Python code defines a custom `LeaderUnknownException` class that inherits from the built-in `Exception`. The constructor (`__init__`) takes one argument: `nodes`, which should be an iterable (like a list or set) of nodes.