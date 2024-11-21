from concurrent.futures import Future

class LldbModelTargetInterruptible:
    def __init__(self):
        pass

    def interrupt(self) -> Future[None]:
        self.get_manager().send_interrupt_now()
        return Future.completed(None)
