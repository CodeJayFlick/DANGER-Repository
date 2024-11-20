Here is the translation of the given Java code into Python:

```Python
class Help:
    help_service = None

    def __init__(self):
        self.help_service = DefaultHelpService()

    @classmethod
    def get_help_service(cls):
        return cls.help_service

    @classmethod
    def install_help_service(cls, service):
        cls.help_service = service
        DockingWindowManager.set_help_service(service)
```

Note that in Python, we don't have a direct equivalent of Java's `package` statement. The class is defined at the top level and can be accessed directly.

Also note that I've assumed you have a `DefaultHelpService` class available for use with this code. If not, you'll need to define or import it separately.

Finally, Python doesn't support static variables like Java does. Instead, we're using an instance variable (`help_service`) and accessing it through the class itself (using `cls`).