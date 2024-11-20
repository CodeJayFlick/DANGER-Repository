Here is the equivalent Python code:

```Python
import collections

class Recognizer:
    def __init__(self):
        pass  # You need to implement this class further

def get_all_recognizers():
    all_recognizers = [Recognizer() for _ in range(10)]  # Replace with actual instances of Recognizer
    return sorted(all_recognizers, key=lambda x: x.priority, reverse=True)

# Note that Python's built-in sorting is stable and does not require a custom comparator.
```

Note:

- The `Comparator` interface from Java has no direct equivalent in Python. Instead, you can use the built-in `sorted()` function with a lambda function as the key to sort your list of recognizers.

- In this code, I've replaced the actual instances of `Recognizer` classes with a simple placeholder (`[Recognizer() for _ in range(10)]`). You should replace these with actual instances of `Recognizer`.

- The Python version does not include any error handling or exception checking.