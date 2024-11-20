Here is the translation of the given Java code into Python:

```Python
class Concat:
    def concat(self, str1: str, str2: str) -> str:
        print(f"!{str1}@{str2}")
        return "done"

    def concat1(self, str1: str, str2: str) -> str:
        x = 0
        sb = StringBuilder("test")
        sb.append("asdf")
        sb.append("asdfsfasdf")
        sb.append("123123")
        print(sb)
        return f"done{x}"

    def print_it(self, str: str):
        print(str)

# Example usage:
c = Concat()
print(c.concat("Hello", "World"))
print(c.concat1("Test", "Example"))
```

Note that Python does not have a direct equivalent to Java's StringBuilder class. However, the `str.format()` method or f-strings can be used for string concatenation in Python.

Also note that there is no need to specify types of variables and function parameters like we do in Java because Python is dynamically typed language.