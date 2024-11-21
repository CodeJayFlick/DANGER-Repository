class AttributedVertex:
    NAME_KEY = "Name"
    VERTEX_TYPE_KEY = "VertexType"

    def __init__(self, id: str, name: str = None):
        self.id = id
        if name is not None:
            self.name = name

    @property
    def name(self) -> str:
        return getattr(self, "_name", "")

    @name.setter
    def name(self, value: str):
        setattr(self, "_name", value)

    @property
    def vertex_type(self) -> str:
        return getattr(self, "_vertex_type", "")

    @vertex_type.setter
    def vertex_type(self, value: str):
        setattr(self, "_vertex_type", value)

    def __str__(self) -> str:
        if self.name == "":
            name = "Unknown"
        else:
            name = self.name

        return f"{name} ({self.id})"

    def __eq__(self, other):
        if not isinstance(other, AttributedVertex):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)
