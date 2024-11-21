class PtyEndpoint:
    def __init__(self):
        pass

    def get_output_stream(self) -> bytes:
        raise NotImplementedError("This end is not local")

    def get_input_stream(self) -> bytes:
        raise NotImplementedError("This end is not local")
