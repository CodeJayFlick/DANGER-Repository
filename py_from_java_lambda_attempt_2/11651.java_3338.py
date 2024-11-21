Here is the translation of the Java code to Python:

```Python
class AddressUtils:
    @staticmethod
    def unsigned_compare(v1: int, v2: int) -> int:
        if v1 == v2:
            return 0
        elif (v1 >= 0 and v2 >= 0):
            return -1 if v1 < v2 else 1
        elif (v1 < 0 and v2 < 0):
            return -1 if v1 < v2 else 1
        elif v1 < 0:
            return 1
        else:
            return -1

    @staticmethod
    def unsigned_subtract(a: int, b: int) -> int:
        return a - b

    @staticmethod
    def unsigned_add(a: int, b: int) -> int:
        return a + b
```

Note that in Python, we don't need to explicitly specify the type of variables like `long` or `int`. The interpreter can infer it based on the value assigned. Also, the method names are camelCase (a convention used by Java), but I've followed PEP 8 guidelines for naming conventions and changed them to underscore_case in Python.