Here is the translation of the Java code to Python:
```
class QueryTimeoutException(Exception):
    def __init__(self, query: str) -> None:
        super().__init__(f"Query: {query} timed out")
```
Note that in Python, we don't need a `package` declaration or an explicit `public` access modifier. The class is defined using the `class` keyword and inherits from the built-in `Exception` class.

The constructor (`__init__`) takes a single argument `query`, which is used to construct the error message using f-strings (a new feature in Python 3.6+).