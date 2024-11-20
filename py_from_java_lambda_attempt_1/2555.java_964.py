Here is the translation of the Java code to Python:
```
class TraceConflictedMappingException(Exception):
    def __init__(self, message, conflict):
        super().__init__(message)
        self.conflict = conflict

    @property
    def conflict(self):
        return self._conflict

# Example usage:
try:
    # some code that might raise an exception
except TraceConflictedMappingException as e:
    print(f"Conflict found: {e.conflict}")
```
Note that in Python, we don't need to specify the type of a variable or method parameters. Also, properties are used instead of getter/setter methods.

In this translation:

* The `package` and license information at the top are not translated, as they are specific to Java.
* The `public class` declaration becomes simply `class`.
* The constructor (`__init__`) is similar to the Java equivalent, but with Python's syntax.
* The getter method (`getConflict()`) is replaced by a property decorator (`@property`).