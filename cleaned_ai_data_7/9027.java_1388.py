import typing as t

class VTMatchOneToManyContext:
    def __init__(self, provider: object, selected_items: t.List[t.Any]) -> None:
        super().__init__(provider, None)
        self.selected_items = selected_items

    @property
    def selected_matches(self) -> t.List[object]:
        return self.selected_items
