Here's the equivalent Python code:

```Python
class NotInSameGroupException(Exception):
    def __init__(self, group, node):
        super().__init__(f"This node {node} is not in the data group {group}")
```

Note that I've removed all Java-specific elements (like `package`, `import`, etc.) and replaced them with Python's equivalent constructs.