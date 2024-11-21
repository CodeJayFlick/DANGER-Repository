Here is the translation of the Java code to Python:

```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class BusinessException(Exception):
    pass


def business_operation(func: callable) -> callable:
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise BusinessException(str(e))
    return wrapper


BusinessOperation = type('BusinessOperation', (), {
    '__call__': lambda self, *args, **kwargs: self.perform()
})

class BusinessOperation(metaclass=BusinessOperation):
    def __init__(self):
        pass

    def perform(self) -> any:
        raise NotImplementedError
```

Note that the `@FunctionalInterface` annotation is not directly translatable to Python. Instead, I defined a metaclass for the `BusinessOperation` class to mimic its behavior.

Also, in Java, the `<T>` notation indicates a generic type parameter. In Python, we don't have explicit generics like Java does, but you can use the built-in `any` type (or any other type that makes sense) as a placeholder.