class UnknownRegister:
    def __init__(self, name: str, description: str, address: int, num_bytes: int,
                 big_endian: bool, type_flags: int):
        super().__init__(name, description, address, num_bytes, big_endian, type_flags)

# Note: In Python, we don't need to define a separate class for the Address type
# since it's not a complex data structure. We can simply use an integer as a proxy.
