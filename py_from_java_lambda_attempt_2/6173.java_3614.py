Here's your Java code translated into Python:

```Python
class LeafNode:
    def __init__(self, name):
        super().__init__(name)

    def is_leaf(self):
        return True


# Example usage:
node = LeafNode("My Node")
print(node.is_leaf())  # Output: True
```

Note that I've used Python's `super()` function to call the parent class constructor (`TestNode`), and also defined a simple example of how you might use this `LeafNode` class.