Here is the equivalent Python code:

```Python
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
```

Note that Python does not have a direct equivalent to Java's generics system. The `register_pluggable_service` and `get_pluggable_service` methods are written in such a way as to avoid the need for explicit type checking, but they do assume that the replacement instances will be of the same class or subclass as the registered instance.

Also note that Python does not have an equivalent to Java's checked exceptions. The `PluggableServiceRegistryException` is raised if there are any issues with registering a pluggable service, and it can be caught using standard try/except blocks in your code.