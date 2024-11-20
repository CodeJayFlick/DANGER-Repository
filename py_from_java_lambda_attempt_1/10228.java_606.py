Here is the translation of the Java code to Python:
```
class ListNodeSTL(T):
    def __init__(self, prev=None, next=None, value=None):
        self.prev = prev
        self.next = next
        self.value = value

    @property
    def stack_use(self):
        return []

# Example usage:
node1 = ListNodeSTL(value="Hello")
node2 = ListNodeSTL(prev=node1, next=node1, value="World")

print(node1.value)  # Output: Hello
print(node2.value)  # Output: World

# Create a new node with default values (null)
node3 = ListNodeSTL()
print(node3.value)  # Output: None
```
Note that I used the `@property` decorator to create a read-only property for the `stack_use` attribute, since there is no equivalent concept in Python.