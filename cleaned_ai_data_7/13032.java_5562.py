class ServiceListener:
    def __init__(self):
        pass

    def service_added(self, interface_class: type, service: object) -> None:
        """Notifies the listener that a service has been added to the tool."""
        ...

    def service_removed(self, interface_class: type, service: object) -> None:
        """Notifies the listener that a service has been removed from the tool."""
        ...
