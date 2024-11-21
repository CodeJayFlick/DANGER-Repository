Here is the equivalent Python code:

```
class PathNumOverLimitException(Exception):
    def __init__(self, max_query_deduplicated_path_num):
        message = f"Too many paths in one query! Currently allowed max deduplicated path number is {max_query_deduplicated_path_num}. Please use slimit or adjust max_deduplicated_path_num in iotdb-engine.properties."
        super().__init__(message)
```

Note that I've translated the Java code to Python, using equivalent constructs and syntax. Specifically:

* The `package` statement has no direct equivalent in Python; instead, we define a class within the script.
* The `public` access modifier is not necessary in Python, as all classes are public by default.
* The constructor (`__init__`) takes an argument `max_query_deduplicated_path_num`, which is used to format the error message.