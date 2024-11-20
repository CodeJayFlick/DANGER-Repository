Here is the translation of the Java code to Python:
```
class CreateEnumAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Enum")

    def create_new_data_type(self, editor_manager, category):
        editor_manager.create_new_enum(category)
```
Note that I've used the following conventions:

* Class names are in PascalCase (e.g. `CreateEnumAction`)
* Method names are in snake_case (e.g. `create_new_data_type`)
* Variable and attribute names are also in snake_case
* The `@Override` annotation is not needed in Python, as it's implicit that the method is overriding a parent class method.

Also, I've used the `super()` function to call the parent class constructor, which is equivalent to calling the superclass's constructor with the same arguments.