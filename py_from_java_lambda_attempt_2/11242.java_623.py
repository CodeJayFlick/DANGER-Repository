Here is the translation of the given Java code into Python:

```Python
class ServiceManager:
    def __init__(self):
        self.services_by_interface = {}
        self.service_listeners = set()
        self.notify_add = True
        self.notifications = []

    def add_service_listener(self, listener):
        self.service_listeners.add(listener)

    def remove_service_listener(self, listener):
        self.service_listeners.remove(listener)

    def set_service_added_notifications_on(self, b):
        if not self.notify_add:
            for notification in self.notifications[:]:
                interface_class, service = notification
                self._notify_service_added(interface_class, service)
                self.notifications.remove(notification)
        self.notify_add = b

    def _notify_service_added(self, interface_class, service):
        for listener in self.service_listeners.copy():
            listener.service_added(interface_class, service)

    def add_service(self, interface_class, service):
        if not isinstance(service, type):
            raise TypeError("Service must be a class")
        list_ = self.services_by_interface.setdefault(type(service), [])
        if service in list_:
            raise AssertionError(f"Same Service implementation cannot be added more than once: {service}")
        list_.append(service)
        if self.notify_add:
            self._notify_service_added(interface_class, service)
        else:
            self.notifications.append((interface_class, service))

    def remove_service(self, interface_class, service):
        list_ = self.services_by_interface.get(type(service), None)
        if list_ is not None and service in list_:
            list_.remove(service)
            if len(list_) == 0:
                del self.services_by_interface[type(service)]
        for listener in self.service_listeners.copy():
            listener.service_removed(interface_class, service)

    def get_service(self, interface_class):
        list_ = self.services_by_interface.get(type(None), None)
        return next((service for service in list_ if isinstance(service, type)), None).cast_to(interface_class) if list_ else None

    def get_services(self, interface_class):
        list_ = self.services_by_interface.get(type(None), None)
        services = [next((service for service in list_ if isinstance(service, type)), None)]
        return services[0].__class__.__subclasses__()

    def is_service(self, service_interface):
        for service_class in self.services_by_interface:
            if service_class == service_interface:
                return True
        return False

    def get_all_services(self):
        all_services = []
        for interface_class, list_ in self.services_by_interface.items():
            for service_impl in list_:
                all_services.append(ServiceInterfaceImplementationPair(interface_class, type(service_impl)))
        return all_services


class ServiceInterfaceImplementationPair:
    def __init__(self, interface_class, implementation):
        self.interface_class = interface_class
        self.implementation = implementation

    @classmethod
    def cast_to(cls, interface_class):
        if not isinstance(cls.implementation, type) or cls.implementation.__class__ != interface_class:
            raise TypeError(f"Implementation {cls.implementation} is not of the correct class for {interface_class}")
        return cls(implementaton=interface_class)
```

This Python code maintains a dictionary `services_by_interface` where keys are service interfaces and values are lists of services that implement those interfaces. It also keeps track of listeners who want to be notified when services are added or removed, using the set `service_listeners`. The method `_notify_service_added` is used internally by the class to notify these listeners.

The methods `add_service`, `remove_service`, and `get_services` manage adding, removing, and retrieving services from this dictionary.