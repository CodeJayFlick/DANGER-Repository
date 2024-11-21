Here is the translation of the Java code to Python:
```
class CompilerConstraint:
    def __init__(self):
        self.compiler_id = None

    def is_satisfied(self, program: 'Program') -> bool:
        return str(program.get_compiler_spec().get_compiler_spec_id()) == str(self.compiler_id)

    def load_constraint_data(self, data: dict) -> None:
        self.compiler_id = data['id']

    def __eq__(self, other):
        if not isinstance(other, CompilerConstraint):
            return False
        return str(other.compiler_id) == str(self.compiler_id)

    def get_description(self) -> str:
        return f"compiler = {self.compiler_id}"
```
Note that I've used Python's built-in `str` function to convert the compiler ID and program compiler spec ID to strings, since Java's `equals()` method is not applicable in this case. Additionally, I've replaced the `@Override` annotations with nothing, as they are not necessary in Python.

Also, please note that I'm assuming you have a `Program` class defined elsewhere in your code, which has methods like `get_compiler_spec()` and `get_compiler_spec_id()`. If such a class does not exist, you will need to define it or modify the above code accordingly.