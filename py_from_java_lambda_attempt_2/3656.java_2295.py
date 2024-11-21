Here is the translation of the Java code to Python:
```
class CreateUnionAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Union")

    def create_new_data_type(self, editor_manager, category):
        editor_manager.create_new_union(category, False)
```
Note that I've kept the same method names and variable names as in the original Java code. In Python, we don't need to specify types for variables or methods, so you won't see any type declarations like `public` or `protected`. Also, Python uses indentation instead of curly braces `{}` to define block-level structure, which is why I've used four spaces to indent each method body.