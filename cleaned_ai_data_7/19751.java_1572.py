class ExprAllGroups:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        return {"all groups": (str, "simple", None)}

    def init(self, exprs=None, matched_pattern=0, is_delayed=False, parse_result=None):
        if not VaultHook().has_group_support():
            Skript.error(VaultHook.NO_GROUP_SUPPORT)
            return False
        return True

    @staticmethod
    @property
    def get_groups(vault_hook: VaultHook) -> list:
        return vault_hook.permission.get_groups()

    def get_return_type(self):
        return str

    def is_single(self):
        return False

    def __str__(self, e=None, debug=False):
        if not isinstance(e, type(None)):
            raise TypeError("Event should be None")
        return "all groups"
