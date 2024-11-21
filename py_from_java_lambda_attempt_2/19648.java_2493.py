Here is a translation of the Java code into equivalent Python:

```Python
class PermissionsExpression:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        return {
            "pattern": r"[(all [[of] the]|the)] permissions (from|of) %players%",
            "return_type": str,
            "expression_type": "property",
        }

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result: dict):
        self.players = exprs[0]

    def get(self, event=None):
        permissions = set()
        for player in self.players:
            for permission_attachment_info in player.get_effective_permissions():
                permissions.add(permission_attachment_info.permission)
        return list(permissions)

    @property
    def is_single(self) -> bool:
        return False

    @property
    def get_return_type(self):
        return str

    def __str__(self, event=None, debug=False):
        if not event and not debug:
            return "permissions of {}".format(self.players)
        else:
            return f"permissions {event} of {self.players}"
```

Please note that this is a translation into Python 3.x.