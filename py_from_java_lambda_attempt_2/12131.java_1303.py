Here is the equivalent Python code:

```Python
import re

class StringMatchQuery:
    def __init__(self, col, search_string, case_sensitive):
        self.col = col
        if not case_sensitive:
            search_string = f".*{re.escape(search_string)}.*"
        else:
            search_string = re.escape(search_string)
        pattern = re.compile(search_string)

    def matches(self, record):
        value = str(record[self.col])
        return bool(re.fullmatch(self.pattern, value))
```

This Python code does the same thing as the Java code. It creates a query that can be used to match string fields in a database with a given search string and an optional case sensitivity flag.

The `__init__` method initializes the query by creating a regular expression pattern based on the search string and the case sensitivity flag. If the case sensitivity is False, it adds .* at the start and end of the search string to make it match any strings that contain the search string anywhere in them. 

The `matches` method checks if the value in the specified column of the record matches the pattern by using a full match with the regular expression.

Please note that Python's re module does not support wildcard matching like Java's Pattern class, so we have to add .* at the start and end of the search string ourselves.