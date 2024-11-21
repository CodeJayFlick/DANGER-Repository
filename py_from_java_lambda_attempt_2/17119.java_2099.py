Here is the translation of the Java code to Python:
```
class SyncConnectionException(Exception):
    def __init__(self, message=""):
        super().__init__(message)
        self.status_code = "SYNC_CONNECTION_EXCEPTION"

def __str__(self):
    return f"Sync Connection Exception: {super().__str__()}"
```
Note that I've made the following changes:

* In Python, we don't need to specify a package name or import statements. The code is simply defined as a class.
* The `serialVersionUID` field in Java has no direct equivalent in Python, so it's been removed.
* The constructor (`__init__`) takes an optional `message` parameter and passes it to the parent class `Exception`. It also sets the `status_code` attribute.
* There is only one constructor in this translation, as there are many ways to create exceptions in Python. If you want to add more constructors or methods, feel free to do so!
* The `__str__` method returns a string representation of the exception.

That's it!