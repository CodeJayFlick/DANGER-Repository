class DebugOutputCallbacks:
    def __init__(self):
        pass

    def output(self, mask: int, text: str) -> None:
        """The interface for receiving output callbacks"""
        # Your callback logic here
        print(f"Mask: {mask}, Text: {text}")
