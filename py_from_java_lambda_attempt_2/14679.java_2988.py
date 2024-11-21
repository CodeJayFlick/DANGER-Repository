Here is the equivalent Python code:

```Python
class Video:
    def __init__(self, id: int, title: str, length: int, description: str, director: str, language: str):
        self.id = id
        self.title = title
        self.length = length
        self.description = description
        self.director = director
        self.language = language

    def __str__(self) -> str:
        return f"{{\"id\": {self.id}, \"title\": \"{self.title}\", \"length\": {self.length}, " \
               f"\"description\": \"{self.description}\", \"director\": \"{self.director}\", \"language\": \"{self.language}\"}}"
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation. The `__str__` method is used instead, which returns the string representation of an object when called with no arguments (like in the case of `print()`).