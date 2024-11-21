Here is the equivalent Python code:

```
class ArtStorageMode:
    k_STORAGE_MODE_UNCOMPRESSED = 0
    k_STORAGE_MODE_LZ4 = 1
    k_STORAGE_MODE_LZ4HC = 2
    k_STORAGE_MODE_COUNT = 3

    @classmethod
    def get(cls, value):
        if not isinstance(value, int) or value < cls.k_STORAGE_MODE_UNCOMPRESSED or value >= cls.k_STORAGE_MODE_COUNT:
            raise ValueError("Invalid ArtStorageMode")
        return [cls.k_STORAGE_MODE_UNCOMPRESSED, cls.k_STORAGE_MODE_LZ4, cls.k_STORAGE_MODE_LZ4HC][value]

    k_DEFAULT_STORAGE_MODE = k_STORAGE_MODE_UNCOMPRESSED
    SIZE = 32

ArtStorageMode.get = classmethod(ArtStorageMode.get)
```

Note that Python does not have an exact equivalent to Java's enum type. Instead, we define a class with static values and methods. The `get` method is defined as a class method using the `@classmethod` decorator.