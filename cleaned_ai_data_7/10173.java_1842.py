class Decision:
    def __init__(self, value: str, decision_path: list[str], source: str):
        self.value = value
        self.decision_path = decision_path
        self.source = source

    @property
    def value(self) -> str:
        return self.value

    @property
    def source(self) -> str:
        return self.source

    @property
    def decision_path(self) -> list[str]:
        return self.decision_path

    def get_decision_path_string(self) -> str:
        return "\n".join(self.decision_path)
