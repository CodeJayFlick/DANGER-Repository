class JdiTargetOutputListener:
    def __init__(self):
        pass

    def output(self, out: str) -> None:
        """The target outputted some text"""
        print(out)
