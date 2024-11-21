class SyncServerManagerMBean:
    def get_rpc_service_status(self):
        # implement this method in your subclass
        pass

    def get_rpc_port(self):
        # implement this method in your subclass
        pass

    def start_service(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def restart_service(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def stop_service(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
