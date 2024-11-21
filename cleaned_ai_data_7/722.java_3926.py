class DbgRegister:
    def __init__(self, name: str, number: int, size: int):
        self.name = name
        self.number = number
        self.size = size

    @classmethod
    def from_description(cls, desc: dict) -> 'DbgRegister':
        return cls(desc['name'], desc['index'], desc['byteLength'])

    def get_name(self) -> str:
        return self.name

    def get_number(self) -> int:
        return self.number

    def get_size(self) -> int:
        return self.size

    def __lt__(self, other):
        return self.number < other.number

    def __str__(self) -> str:
        return f"<{type(self).__name__} {self.name} ({self.number})>"

    def is_base_register(self) -> bool:
        if not hasattr(self, 'desc'):
            return True
        return self.desc['subregMaster'] == 0

# Example usage:
register1 = DbgRegister("my register", 10, 4)
print(register1.get_name())  # prints: my register
print(register1.get_number())  # prints: 10
print(register1.get_size())    # prints: 4

register2 = DbgRegister.from_description({
    'name': "another register",
    'index': 20,
    'byteLength': 8
})
print(register2)              # prints: <DbgRegister another register (20)>
