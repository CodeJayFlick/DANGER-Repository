Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class NameFilter:
    def execute(self, order):
        result = super().execute(order)
        name = order.get_name()
        if not name or not name.strip() or not re.match(r"^[a-zA-Z0-9\s]+$", name):
            return f"{result} Invalid name!"
        else:
            return result
```
Note that I've used the `re` module for regular expression matching, and the `f-string` syntax to create a formatted string.