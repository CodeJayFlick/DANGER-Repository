Here is the equivalent Python code:

```Python
class DataTypeConflictException(Exception):
    def __init__(self, dt1=None, dt2=None, message=""):
        super().__init__(message)
        self.datatype1 = dt1
        self.datatype2 = dt2

def get_conflicting_data_types(self):
    return [self.datatype1, self.datatype2]
```

Note that Python does not have a direct equivalent to Java's `extends` keyword. Instead, we can use inheritance and override the parent class's constructor (`__init__`) in our own class.

Also note that Python has no concept of private variables like Java's `private`. However, it is common practice to prefix variable names with an underscore (e.g., `_datatype1`) if they are intended to be private.