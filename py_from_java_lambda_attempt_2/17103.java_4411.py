Here is the equivalent Python code:

```Python
class OutOfTTLException(Exception):
    def __init__(self, insertion_time, time_lower_bound):
        message = f"Insertion time [{insertion_time}] is less than ttl time bound [{time_lower_bound}]"
        super().__init__(message)

# Example usage:
if __name__ == "__main__":
    try:
        raise OutOfTTLException(1643723400, 1643730000)
    except Exception as e:
        print(e)
```

Note that Python does not have a direct equivalent to Java's `package` statement. The code above is simply the translation of the provided Java class into Python.