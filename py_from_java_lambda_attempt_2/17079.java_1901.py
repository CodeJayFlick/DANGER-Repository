Here is the translation of the Java code to Python:
```
class LoadConfigurationException(Exception):
    def __init__(self, message=None, cause=None):
        if cause is None:
            super().__init__(message)
        else:
            super().__init__(message, cause)

serialVersionUID = -1950532739374479184

def get_serial_version_id():
    return serialVersionUID
```
Note that in Python, we don't need to declare the class as `public` or specify a package name. Also, the concept of "serialization" is not directly equivalent to Java's `serialVersionUID`, so I've simply defined it as a constant variable.

The constructor (`__init__`) takes two optional arguments: `message` and `cause`. If only one argument is provided (i.e., `cause` is None), we call the parent class's constructor with that message. If both are provided, we pass them to the parent class's constructor.