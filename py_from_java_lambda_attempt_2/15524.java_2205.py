Here is the translation of the given Java code into equivalent Python:

```Python
class NDIndexFullPick:
    def __init__(self, indices: 'NDArray', axis: int):
        self.indices = indices
        self.axis = axis

def from_index(index: 'NDIndex', target_shape) -> Optional['NDIndexFullPick']:
    full_pick = None
    for el in index.get_indices():
        if isinstance(el, NDIndexAll):
            pass  # Do nothing as we're just incrementing the axis
        elif isinstance(el, NDIndexPick):
            if full_pick is not None:
                raise UnsupportedOperationException("Only one pick per get is currently supported")
            else:
                full_pick = NDIndexFullPick(el.get_indices(), el.axis)
        else:
            return Optional.empty()  # Invalid dim for fullPick

    return Optional.ofNullable(full_pick)

def get_indices(self) -> 'NDArray':
    return self.indices

def get_axis(self) -> int:
    return self.axis
```

Note that Python does not have direct equivalent of Java's `Optional` class. Instead, we can use the built-in `None` value to represent an absent or missing value.

Also note that in Python, you don't need to specify types for variables and function parameters like you do in Java.