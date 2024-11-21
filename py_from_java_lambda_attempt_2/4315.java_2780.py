Here is the translation of the Java code to Python:
```
class FoundStringToProgramLocationTableRowMapper:
    def map(self, row_object: 'FoundString', data: 'Program', service_provider: object) -> 'ProgramLocation':
        return ProgramLocation(data, row_object.get_address())

# Note: In Python, we don't need an explicit `extends` clause or a constructor.
```
Here's what I did:

* Replaced the Java package declaration with nothing (since Python doesn't have packages in the same way).
* Translated the class name and method signature to Python syntax. The `@Override` annotation is not needed in Python, since we're simply defining a new method that happens to have the same signature as an existing one.
* Replaced Java types (`public`, `class`, etc.) with their equivalent Python constructs (e.g., no explicit type declaration for variables).
* Kept the method implementation mostly unchanged, just translating the syntax.