class Builder:
    def __init__(self):
        self.builders = {}

    def add(self, name: str, supplier) -> None:
        if not isinstance(name, str):
            raise TypeError("Name must be a string")
        self.builders[name] = supplier

# Example usage:
builder = Builder()
builder.add('gun', lambda: Gun())
