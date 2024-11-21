class DualProgramLocationPluginEvent:
    NAME = "DualProgramLocation"

    def __init__(self, src: str, loc: dict, program_name: str):
        self.src = src
        self.loc = loc
        self.program_name = program_name

    @property
    def location(self) -> dict:
        return self.loc

    @property
    def program_name(self) -> str:
        return self.program_name


# Example usage:

if __name__ == "__main__":
    event1 = DualProgramLocationPluginEvent("src", {"address": "0x12345678"}, "program_name")
    print(event1.location)
    print(event1.program_name)

    event2 = DualProgramLocationPluginEvent("src", {"address": "0x23456789"}, "another_program_name")
    print(event2.location)
    print(event2.program_name)
