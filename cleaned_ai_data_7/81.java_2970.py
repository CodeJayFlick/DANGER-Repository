class DebuggerInterpreterProvider:
    def __init__(self, plugin, interpreter, visible):
        super().__init__(plugin, interpreter, visible)
        self.sub_title = None

    def set_sub_title(self, subTitle: str) -> None:
        self.sub_title = subTitle
        super().set_sub_title(subTitle)

    def get_sub_title(self) -> str:
        return self.sub_title
