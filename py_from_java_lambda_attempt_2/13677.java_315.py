Here is the equivalent Python code:

```Python
class AbstractDocument:
    def __init__(self, properties: dict):
        if not properties:
            raise ValueError("properties dictionary is required")
        self.properties = properties

    def put(self, key: str, value) -> None:
        self.properties[key] = value

    def get(self, key: str) -> object:
        return self.properties.get(key)

    def children(self, key: str, constructor: callable) -> Stream[object]:
        child_value = self.get(key)
        if child_value is not None and isinstance(child_value, list):
            return (Stream.from_iterable(map(constructor, child_value)))
        else:
            return Stream.empty()

    def __str__(self) -> str:
        builder = StringBuilder()
        builder.append(self.__class__.__name__)
        builder.append('[')
        for key, value in self.properties.items():
            builder.append(f'[{key} : {value}]')
        builder.append(']')
        return builder.toString()


from typing import Stream

Stream = type(str('Stream', (object,), {'empty': lambda: self}))

class StringBuilder:
    def __init__(self):
        self.builder = ''

    def append(self, value) -> None:
        self.builder += str(value)

    def toString(self) -> str:
        return self.builder
```

Please note that Python does not have direct equivalent of Java's Stream API. The `Stream` class in the above code is a simple implementation and may not support all operations available on Java streams.

Also, please be aware that this translation was done manually and might contain errors or inaccuracies.