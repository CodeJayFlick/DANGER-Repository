class PluggableServiceRegistry:
    _map = {}

    @classmethod
    def register_pluggable_service(cls, pluggable_service_class: type, replacement_instance):
        if not cls._map.get(pluggable_service_class):
            # no entry yet, just put it in
            cls._map[pluggable_service_class] = replacement_instance
            return

        registered_instance = cls._map[pluggable_service_class]
        already_registered_class = type(registered_instance)
        replacement_class = type(replacement_instance)

        if already_registered_class.__subclasses__.get() and issubclass(replacement_class, already_registered_class):
            # we're making the service more specific
            cls._map[pluggable_service_class] = replacement_instance
            return

        if issubclass(already_registered_class, replacement_class):
            # we're trying to be more generic; silently drop it
            return

        raise PluggableServiceRegistryException(pluggable_service_class, already_registered_class, replacement_class)

    @classmethod
    def get_pluggable_service(cls, pluggable_service_class: type) -> object:
        return cls._map.get(pluggable_service_class)
