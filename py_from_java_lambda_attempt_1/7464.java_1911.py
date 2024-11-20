Here is the translation of the Java code to Python:
```
class FunctionGraphEmptyGraphActionContext:
    def __init__(self, function_graph_provider):
        super().__init__(function_graph_provider, function_graph_provider.get_program())

    def should_show_satellite_actions(self) -> bool:
        return True
```
Note that I've used the following translations:

* `public` classes and methods become Python's built-in `class` and method definitions.
* Java's `extends` keyword becomes Python's inheritance syntax (`super().__init__()`).
* Java's `@Override` annotation is not needed in Python, as it's implicit when overriding a parent class method.
* Java's `return true;` statement becomes Python's simple `return True`.
* The rest of the code remains largely unchanged.