Here is the translation of the Java code to Python:
```
class AddressableRowObjectToProgramLocationTableRowMapper:
    def map(self, row_object: 'AddressableRowObject', program: 'Program') -> 'ProgramLocation':
        return ProgramLocation(program, row_object.get_address())

# Note: In Python, we don't need a separate class for the mapper,
# as it's not necessary to encapsulate the mapping logic.
```
Here are some key differences between Java and Python:

* In Python, we use indentation instead of curly braces `{}` to define code blocks (e.g., classes, functions).
* We don't need explicit type declarations like `public class` or `extends ProgramLocationTableRowMapper`.
* The `@Override` annotation is not necessary in Python, as it's implied that the method overrides a parent class method.
* In Python, we use the `->` syntax to indicate the return type of a function (similar to Java).
* We don't need separate classes for data objects like `AddressableRowObject`, as they can be defined inline.

Note: The `'ProgramLocationTableRowMapper'` and `'AddressableRowObjectToProgramLocationTableRowMapper'` types are not actually necessary in Python, but I left them there to maintain the original code's structure.