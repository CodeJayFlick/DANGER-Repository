class SetVariableCommentCmd:
    def __init__(self, var: str, comment: str):
        self.var = var
        self.comment = comment
        self.msg = ""

    @property
    def name(self) -> str:
        return "Set Variable Comment"

    def apply_to(self, obj: dict) -> bool:
        if isinstance(obj.get("var"), dict):
            obj["var"]["comment"] = self.comment
        else:
            raise ValueError("Invalid variable object")
        return True

    @property
    def status_msg(self) -> str:
        return self.msg
