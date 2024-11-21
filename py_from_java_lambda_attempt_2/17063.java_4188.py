Here is the equivalent Python code:

```
class UpgradeCheckStatus:
    BEGIN_UPGRADE_FILE = 1
    AFTER_UPGRADE_FILE = 2
    UPGRADE_SUCCESS = 3

    def __init__(self, check_status_code):
        self.check_status_code = check_status_code

    @property
    def check_status_code(self):
        return self._check_status_code

    def __str__(self):
        return str(self.check_status_code)
```

Note that Python does not have an equivalent to Java's `enum` type. Instead, we define a class with static variables and use the `__init__`, `@property`, and `__str__` methods to implement similar functionality.