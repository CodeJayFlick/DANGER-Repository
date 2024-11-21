Here is the translation of the Java code to Python:
```
import abc

class SshJoinGdbModelHost(abc.ABC):
    def getModelFactory(self) -> dict:
        return {"SSH username": input("Enter SSH username:"),
                "Use existing session via new-ui": True}

    def getFactoryOptions(self) -> dict:
        try:
            return self.getModelFactory()
        except Exception as e:
            raise AssertionError("Cancelled", e)
```
Note that I used the `abc` module to implement abstract methods, since Python does not have a built-in equivalent of Java's `@Override` annotation. Additionally, I replaced the `Map.ofEntries()` method with a dictionary comprehension, and the `promptUser()` method is simply an input prompt in Python.

Also, please note that this translation assumes that you want to keep the same functionality as the original code, but it may not be exactly equivalent due to differences between Java and Python.