Here is the translation of the Java code to Python:
```
class QueryInBatchStatementException(Exception):
    def __init__(self, statement: str) -> None:
        message = f"Query statement not allowed in batch: [{statement}]"
        super().__init__(message)
        self.status_code = TSStatusCode.QUERY_NOT_ALLOWED

TSStatusCode = int  # assuming this is an enum or a constant
```
Note that I've made the following changes:

* In Python, we don't need to specify package names like `org.apache.iotdb.db.exception`. Instead, we define our own classes and functions.
* The `serialVersionUID` field in Java has no direct equivalent in Python. We can simply omit it or replace it with a unique identifier if needed.
* The constructor (`__init__`) takes only one argument, the statement string, which is used to create an exception message using f-strings (Python 3.6+).
* I've assumed that `TSStatusCode` is an integer constant or enum value in Java and translated it directly to a Python integer.

This code defines a custom exception class `QueryInBatchStatementException` with a constructor that takes a statement string as input, creates an error message using f-strings, and sets the status code to `QUERY_NOT_ALLOWED`.