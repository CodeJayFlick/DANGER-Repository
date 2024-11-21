Here is the equivalent Python code:

```
class DBOpenMode:
    CREATE = (DBConstants.CREATE,)
    UPDATE = (DBConstants.UPDATE,)
    READ_ONLY = (DBConstants.READ_ONLY,)
    UPGRADE = (DBConstants.UPGRADE,)

    def __init__(self, open_mode):
        self.open_mode = open_mode

    @property
    def to_integer(self):
        return self.open_mode


class DBConstants:
    CREATE = 0
    UPDATE = 1
    READ_ONLY = 2
    UPGRADE = 3
```

Note that Python does not have an exact equivalent of Java's enum type. Instead, we use a class with static variables and methods to achieve similar functionality.