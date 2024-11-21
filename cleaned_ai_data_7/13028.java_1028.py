class PluggableServiceRegistryException(Exception):
    def __init__(self, pluggable_service_class, already_registered_pluggable_service_class,
                 pluggable_service_replacement_instance_class):
        message = f"{pluggable_service_class.__name__} already has registered instance of type {already_registered_pluggable_service_class.__name__}" \
                   f" which is not a super- or subclass of {pluggable_service_replacement_instance_class.__name__}"
        super().__init__(message)
