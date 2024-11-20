Here is the translation of the given Java code into equivalent Python:

```Python
class CustomerCore:
    def __init__(self):
        self.roles = {}

    def add_role(self, role: 'Role') -> bool:
        if not isinstance(role.instance(), dict) or len(role.instance()) == 0:
            return False

        for key in role.instance():
            self.roles[role] = role.instance()[key]
            return True
        return False

    def has_role(self, role: 'Role') -> bool:
        return role in self.roles

    def remove_role(self, role: 'Role') -> bool:
        if role not in self.roles or self.roles.pop(role) is None:
            return False
        return True

    def get_role(self, role: 'Role', expected_role_class: type) -> Optional['Customer']:
        instance = self.roles.get(role)
        if isinstance(instance, dict):
            for key in instance:
                if isinstance(key, str) and key.startswith(expected_role_class.__name__ + "_"):
                    return Optional.of(type(str).type)(instance[key])
        return None

    def __str__(self):
        roles_str = ', '.join(map(str, self.roles.keys()))
        return f"CustomerCore(roles={roles_str})"
```

Please note that Python does not have direct equivalent of Java's `Map`, `Optional` and other utility classes. Also, the type system in Python is dynamic, so you don't need to specify types for variables or function parameters like you do in Java.