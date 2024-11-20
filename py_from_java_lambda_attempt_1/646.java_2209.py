Here is the translation of the given Java code into Python:

```Python
class DbgSetActiveSessionCommand:
    def __init__(self, manager, session):
        self.manager = manager
        self.session = session

    def invoke(self):
        if self.session is not None:
            id = self.session.get_id()
            if id is not None:
                self.manager.get_system_objects().set_current_system_id(id)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or the concept of classes extending other classes (like `extends AbstractDbgCommand< Void >`). The equivalent code in Python uses a class definition and method definitions.