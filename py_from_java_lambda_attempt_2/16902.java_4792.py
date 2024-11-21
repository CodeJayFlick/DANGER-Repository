Here is the translation of the Java code to Python:
```
import os

class LocalFileAuthorizer:
    def __init__(self):
        config = IoTDBConfig()
        self.user_manager = LocalFileUserManager(os.path.join(config.system_dir, "users"))
        self.role_manager = LocalFileRoleManager(os.path.join(config.system_dir, "roles"))

    @property
    def is_admin(self, username: str) -> bool:
        return config.admin_name == username

class IoTDBConfig:
    system_dir = ""

class LocalFileUserManager:
    def __init__(self, user_dir):
        self.user_dir = user_dir

class LocalFileRoleManager:
    def __init__(self, role_dir):
        self.role_dir = role_dir
```
Note that I had to make some assumptions about the Python equivalent of Java classes and methods. For example:

* In Java, `IoTDBConfig` is a class with a static method `getInstance()` that returns an instance of itself. In Python, I simply defined it as a regular class.
* The `@Override` annotation in Java indicates that a method overrides a method from its superclass. In Python, we don't need this annotation because the concept of overriding methods doesn't exist at the same level (Python is dynamically typed).
* The `throws AuthException` clause in Java's constructor is not directly equivalent to anything in Python. I simply removed it.
* The `boolean isAdmin(String username)` method returns a boolean value, which can be represented as a simple function that takes a string and returns a bool.

Please note that this translation may not work perfectly without further testing and refinement.