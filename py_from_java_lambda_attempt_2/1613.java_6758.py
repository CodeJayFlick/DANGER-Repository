Here is the translation of the Java code into Python:

```Python
class LldbSessionSelectedEvent:
    def __init__(self, session):
        self.id = DebugClient.get_id(session)
        self.session = session

    @property
    def id(self):
        return self._id

    @property
    def session(self):
        return self._session


# Assuming you have a class called DebugClient with the following method:
class DebugClient:
    @staticmethod
    def get_id(session):
        # Your code here to implement this method
        pass
```

Please note that I've made some assumptions about your Python environment. For example, I assumed `DebugClient` is a class in your program and it has an attribute called `get_id`. You would need to define the `DebugClient` class with its methods for this code to work correctly.

Also, please be aware that there are no direct equivalents of Java's abstract classes or interfaces in Python. If you want similar functionality, you could use a base class (like I did here) and have your other classes inherit from it.