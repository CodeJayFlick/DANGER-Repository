Here is the translation of the Java code to Python:
```
class UngroupAllVertexFunctionGraphJob:
    def __init__(self, controller):
        self.controller = controller
        self.is_finished = False

    def execute(self, listener):
        try:
            self.controller.ungroup_all_vertices()
        finally:
            self.is_finished = True
            listener.job_finished(self)

    def can_shortcut(self):
        return False

    def shortcut(self):
        raise UnsupportedOperationException("Cannot shortct job: " + str(self))

    @property
    def is_finished(self):
        return self._is_finished

    @is_finished.setter
    def is_finished(self, value):
        self._is_finished = value

    def dispose(self):
        self.is_finished = True

    def __str__(self):
        return "Ungroup All Group Vertices Job"
```
Note that I've used Python's built-in `property` decorator to implement the `isFinished()` method, which is equivalent to Java's getter/setter pattern. Additionally, I've replaced the `throw new UnsupportedOperationException("Cannot shortct job: " + this);` line with a simple `raise` statement in Python.