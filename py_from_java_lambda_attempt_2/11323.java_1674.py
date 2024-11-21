Here is the translation of the Java code to Python:
```
import ghidra_framework_model_project_manager as project_manager

class TestProjectManager(project_manager.DefaultProjectManager):
    _project_manager = None

    @classmethod
    def get(cls):
        if cls._project_manager is None:
            cls._project_manager = TestProjectManager()
        return cls._project_manager

    def __init__(self):
        super().__init__()
```
Note that I've used the `ghidra_framework_model_project_manager` module as a placeholder, since it's not clear what this module would contain in Python. You may need to modify or replace this import statement depending on your specific use case.

Also, keep in mind that Python is an object-oriented language and does not have direct equivalents of Java concepts like `synchronized`, `public`, etc. The code above uses the equivalent constructs available in Python (e.g., class methods, instance variables).