Here is the equivalent Python code:

```Python
class Role:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    BORROWER = "Borrower"
    INVESTOR = "Investor"

    _instances = {}

    def instance(self, role_type: str) -> Optional[CustomerRole]:
        if role_type not in self._instances:
            try:
                self._instances[role_type] = getattr(CustomerRoles(), role_type)
            except (AttributeError, TypeError):
                self.logger.error("error creating an object", exc_info=True)

        return self._instances.get(role_type)


class CustomerRole:
    pass


# Usage
if __name__ == "__main__":
    role = Role()
    borrower_role = role.instance(Role.BORROWER)
    investor_role = role.instance(Role.INVESTOR)
```

Please note that Python does not have direct equivalent of Java's enum. However, we can achieve similar functionality using class and static variables in Python.

Also, the `Optional` type is not a built-in type in Python but it can be implemented as follows:

```Python
from typing import Optional

class Optional:
    def __init__(self, value):
        self.value = value

    @staticmethod
    def of(value):
        return Optional(value)

    def empty(self):
        return None  # or some other default value


# Usage
optional_value: Optional[int] = Optional.of(1)
print(optional_value)  # prints: <__main__.Optional object at 0x7f8a5e2d9c40>
```

However, Python's built-in `None` can be used to represent the absence of a value.