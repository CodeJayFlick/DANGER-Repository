Here is the translation of the given Java code into Python:

```Python
class IsNormalized:
    def __init__(self):
        pass

    @property
    def description(self):
        return "Checks whether a vector is normalized i.e. length of 1"

    @property
    def examples(self):
        return ["vector of player's location is normalized"]

    @property
    def name(self):
        return "Is Normalized"

    @property
    def since(self):
        return "2.5.1"

    @property
    def required_plugins(self):
        return ["Minecraft 1.13.2+"]

    def check(self, vector: 'Vector') -> bool:
        if hasattr(vector, 'is_normalized'):
            return vector.is_normalized()
        else:
            raise AttributeError("The given object does not have an is_normalized method")

class Vector:
    def __init__(self):
        pass

    @property
    def is_normalized(self) -> bool:
        # This function should be implemented based on the actual implementation of 'isNormalized' in Java.
        return False  # Replace this with your logic.

# Registering the class for usage
register = lambda cls, name, *args: globals()[name] = type(name, (cls,), {'__init__': lambda self, *args: None})
register(IsNormalized.__class__, 'Is Normalized', ('Vector',))
```

Please note that this translation is not a direct conversion from Java to Python. The `@property` decorator in the given code is used for defining getter and setter methods for properties of an object. In Python, we can achieve similar functionality using property() function or by implementing __getattribute__() method.

Also, please replace the comment inside Vector's is_normalized method with your actual logic based on how you want to check if a vector is normalized in your application.