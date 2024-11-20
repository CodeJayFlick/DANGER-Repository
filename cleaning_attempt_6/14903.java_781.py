class BaseEntity:
    def __init__(self):
        pass

    @property
    def id(self) -> int | None:
        raise NotImplementedError("Subclasses must implement getId()")

    @id.setter
    def id(self, value: int | None) -> None:
        self._id = value

    @property
    def name(self) -> str:
        raise NotImplementedError("Subclasses must implement getName()")

    @name.setter
    def name(self, value: str) -> None:
        self._name = value

    def __str__(self):
        return f"BaseEntity(id={self.id}, name='{self.name}')"
