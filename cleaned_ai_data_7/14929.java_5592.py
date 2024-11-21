class ServiceLocator:
    _cache = {}

    def __init__(self):
        pass

    @classmethod
    def get_service(cls, service_jndi_name: str) -> dict:
        if service_jndi_name in cls._cache:
            return cls._cache[service_jndi_name]
        else:
            # If we are unable to retrieve anything from cache, then lookup the service and add it in the cache map
            ctx = InitContext()  # Assuming you have an 'InitContext' class defined elsewhere
            service_obj = ctx.lookup(service_jndi_name)
            if service_obj is not None:  # Only cache a service if it actually exists
                cls._cache[service_jndi_name] = service_obj
            return service_obj

class ServiceCache:
    _services = {}

    def get_service(self, service_jndi_name):
        return self._services.get(service_jndi_name)

    def add_service(self, service_obj):
        self._services[service_obj['jndiName']] = service_obj


# Assuming you have an 'InitContext' class defined elsewhere
class InitContext:
    @classmethod
    def lookup(cls, service_jndi_name: str) -> dict:
        # Your logic to look up the service goes here
        pass

