class UnimplError:
    def __init__(self, string, instruction_length):
        self.instruction_length = instruction_length
        super().__init__(string)

if __name__ == "__main__":
    pass
