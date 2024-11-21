from concurrent.futures import Future

class JdiModelTargetInterruptible:
    def __init__(self):
        pass

    def interrupt(self) -> Future[None]:
        return Future()
