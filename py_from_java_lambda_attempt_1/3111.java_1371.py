Here is the translation of the given Java code into equivalent Python:

```Python
class SearchMnemonicsNoOpsNoConstScript:
    def run(self):
        self.set_state(SLMaskControl(True, False, False, False))
        self.load_selected_instructions()
        self.execute_search()

# Define a class for SLMaskControl
class SLMaskControl:
    def __init__(self, mask_control1, mask_control2, mask_control3, mask_control4):
        self.mask_control1 = mask_control1
        self.mask_control2 = mask_control2
        self.mask_control3 = mask_control3
        self.mask_control4 = mask_control4

# Define a class for SearchBaseExtended (assuming it's equivalent to Python's object)
class SearchBaseExtended:
    def __init__(self):
        pass

    # Assuming setState is defined elsewhere, this method sets the state of an instance.
    def set_state(self, state):
        self.state = state
```

Please note that I've made some assumptions about the original Java code. For example:

- The `SearchBaseExtended` class in Python doesn't have any specific methods or attributes like it does in Java. It's just a base class for inheritance.
- The `SLMaskControl` class is defined as an object with four boolean properties, but its actual behavior might be different depending on the context of your program.

This translation assumes that you're using Python 3.x and doesn't include any specific imports or modules unless they are necessary to run this code.