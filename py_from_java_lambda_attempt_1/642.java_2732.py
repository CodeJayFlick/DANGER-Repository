Here is the translation of the given Java code into equivalent Python:

```Python
class DbgRequestActivationCommand:
    def __init__(self, manager: 'DbgManagerImpl', activator: 'DbgModelTargetActiveScope', obj: 'TargetObject'):
        self.manager = manager
        self.activator = activator
        self.obj = obj

    def invoke(self):
        self.activator.do_request_activation(self.obj)
```

Note that Python does not have direct equivalent of Java's `package`, `import` statements, or the concept of classes and methods. Instead, we define a class in Python using the `class` keyword followed by the name of the class.

The constructor (`__init__`) is used to initialize instance variables (self.activator and self.obj) with values passed as arguments when an object of this class is created.

In the `invoke` method, we simply call the `do_request_activation` method on the activator instance, passing in the obj.