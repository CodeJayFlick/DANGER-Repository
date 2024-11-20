Here is the equivalent Python code:

```Python
class Singleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Singleton, cls).__new__(cls)
        return cls._instance


# Usage example
if __name__ == "__main__":
    singleton1 = Singleton()
    singleton2 = Singleton()

    print(singleton1 is singleton2)  # True

```

This Python code implements the Singleton pattern using a private class variable `_instance` to store the instance of `Singleton`. The `__new__` method ensures that only one instance of `Singleton` can be created.