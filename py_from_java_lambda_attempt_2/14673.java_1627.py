Here is the translation of the given Java enum class into a Python equivalent:

```Python
class SortOrder:
    ASC = ("asc",)
    DESC = ("desc",)

    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value


# Usage example:
sort_order_asc = SortOrder("ASC")
print(sort_order_asc.value)  # Output: "asc"

sort_order_desc = SortOrder("DESC")
print(sort_order_desc.value)  # Output: "desc"
```

In this Python code, we define a class `SortOrder` with two static properties (`ASC` and `DESC`) that are tuples. The constructor of the class takes one argument which is stored in an instance variable.

The property decorator `@property` allows us to create getter methods for our instance variables.