from concurrent.futures import Future

class DbgModelTargetDetachable:
    def __init__(self):
        pass

    def detach(self) -> Future[None]:
        process = self.get_manager().get_current_process()
        return self.get_model().gate_future(process.detach())

    def get_manager(self):
        # This method should be implemented in the subclass
        raise NotImplementedError("Method not implemented")

    def get_model(self):
        # This method should be implemented in the subclass
        raise NotImplementedError("Method not implemented")
