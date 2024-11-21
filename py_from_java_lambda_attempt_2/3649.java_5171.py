Here is the translation of the Java code to Python:
```
class CreateFunctionDefinitionAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Function Definition")

    def create_new_data_type(self, editor_manager, category):
        editor_manager.create_new_function_definition(category)
```
Note that I've kept the same class and method names as in the original Java code. However, Python is an object-oriented language with a different syntax than Java, so some changes were necessary to translate the code.

Here's what changed:

* In Python, we don't need explicit `public` or `private` access modifiers.
* The constructor (`__init__`) takes only one argument, `plugin`, whereas in Java it took two arguments. This is because Python doesn't require a separate constructor method; instead, you can define the initialization logic directly inside the class definition.
* In Python, we use the `super()` function to call the parent class's constructor (or any other method), rather than using an explicit `super` keyword like in Java.
* The `@Override` annotation is not needed in Python because it doesn't have a concept of overriding methods. Instead, you can simply define the same method name and signature as the one being overridden.

That's it!