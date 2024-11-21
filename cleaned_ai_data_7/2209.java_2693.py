from concurrent.futures import Future

class TargetResumable:
    def __init__(self):
        pass

    def resume(self) -> Future[None]:
        # implement your logic here to handle resuming a target
        return Future(None)
