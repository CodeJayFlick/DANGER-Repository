class AbstractGdbThreadGroupEvent:
    def __init__(self, tail):
        self.iid = None  # Initialize iid as None for now
        super().__init__(tail)
        try:
            self.iid = GdbParsingUtils.parse_inferior_id(self.get_info()["id"])
        except Exception as e:  # Assuming any exception will be caught here
            raise GdbParseError("Failed to parse the tail") from e

    def get_inferior_id(self):
        return self.iid


class GdbEventWithFields:
    pass


class GdbParsingUtils:
    @staticmethod
    def parse_inferior_id(id_str):
        # Implement your parsing logic here. For now, just returning the id string.
        return id_str

    class GdbParseError(Exception):
        pass


# Example usage:

if __name__ == "__main__":
    event = AbstractGdbThreadGroupEvent("some_tail")
    print(event.get_inferior_id())
