class LldbConsoleOutputEvent:
    def __init__(self, info=None):
        self.mask = 0
        if info is not None:
            self.info = info
            self.text = SBEvent.get_c_string_from_event(info.event)
            stream = SBStream()
            success = info.event.get_description(stream)
            if success:
                print(self, stream.get_data())
                if self.text is None:
                    self.text = stream.get_data()

    def __init__(self, mask: int, text: str):
        self.mask = mask
        self.text = text

    @property
    def output(self) -> str:
        return self.text

    @property
    def mask_(self) -> int:
        return self.mask


class SBEvent:
    @staticmethod
    def get_c_string_from_event(event):
        # This method should be implemented based on the actual functionality of SBEvent in Java.
        pass


class SBStream:
    def __init__(self):
        pass

    def get_data(self) -> str:
        # This method should be implemented based on the actual functionality of SBStream in Java.
        return ""


# Example usage
if __name__ == "__main__":
    class DebugProcessInfo:
        def __init__(self, event=None):
            self.event = event

    info = DebugProcessInfo()
    event = LldbConsoleOutputEvent(info)
    print(event.output)  # This will call the getter method for 'output' property.
