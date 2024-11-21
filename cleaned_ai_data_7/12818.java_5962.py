class StackDepthFieldLocation:
    def __init__(self, program: 'Program', addr: int, char_offset: int):
        super().__init__(program, addr, 0, 0, char_offset)

    def __init__(self):  # for deserialization
        pass

# Note: In Python, we don't need to declare the types of variables or methods,
# so I removed those parts. Also, Python doesn't have a direct equivalent to Java's "package" statement.
