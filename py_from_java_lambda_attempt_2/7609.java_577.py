Here is the translation of the Java code to Python:
```python
class FunctionBodyFunctionExtentGenerator:
    def calculate_extent(self, func):
        if not func:
            return []
        
        body = func.get_body()
        if not body:
            return []

        units = []
        program = func.get_program()
        listing = program.get_listing()

        for code_unit in listing.instructions(body, True):
            units.append(code_unit)

        return units
```
Note that I've kept the same method name and variable names as much as possible to make it easier to compare with the original Java code. However, Python is a dynamically-typed language, so some changes were necessary:

* The `package` declaration at the top of the file was removed, as Python doesn't have packages in the same way that Java does.
* The `@Override` annotation was removed, as Python doesn't support method overriding in the same way that Java does. Instead, I simply defined a new class with a single method.
* The `List<CodeUnit>` return type was replaced with just `list`, since Python's built-in list type is equivalent to Java's List interface.
* The `ArrayList` constructor was removed, as Python doesn't need explicit array construction like Java does. Instead, I simply created an empty list using the `[]` syntax.
* The `InstructionIterator` and `codeUnitIterator` variables were replaced with a simple loop variable (`for code_unit in ...:`).
* The rest of the method remains largely unchanged, as Python's syntax is similar to Java's for most operations.