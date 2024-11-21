class TraceActivatedPluginEvent:
    NAME = "Trace Location"

    def __init__(self, source, coordinates):
        super().__init__(source, self.NAME)
        self.coordinates = coordinates

    @property
    def active_coordinates(self):
        return self.coordinates


# Example usage:
if __name__ == "__main__":
    class DebuggerCoordinates:  # equivalent to the Java class
        pass

    event = TraceActivatedPluginEvent("some_source", DebuggerCoordinates())
    print(event.active_coordinates)  # prints whatever is in DebuggerCoordinates()
