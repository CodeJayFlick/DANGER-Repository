Here is the translation of the Java code into Python:

```Python
class FilterHolder:
    def __init__(self, filter: object, servlet_context):
        self.filter = filter
        self.servlet_context = servlet_context
        self.filter_initialized = False

        if hasattr(filter.__class__, 'WebFilter'):
            annotation = getattr(filter.__class__, 'WebFilter')
            self.filter_name = annotation.name()
            init_params = {param.name(): param.value() for param in annotation.initParams()}
            registration = Registration(annotation)
        else:
            self.filter_name = filter.__class__.__name__
            init_params = {}
            registration = None

    def is_filter_initialized(self):
        return self.filter_initialized

    @property
    def get_filter(self):
        return self.filter

    @property
    def get_filter_config(self):
        # Default implementation of the FilterConfig object.
        class Config:
            pass

        return Config()

    @property
    def get_registration(self):
        return registration

    @property
    def filter_name(self):
        return self._filter_name

    @filter_name.setter
    def set_filter_name(self, value):
        self._filter_name = value

    @property
    def init_parameters(self):
        return self._init_params

    @property
    def servlet_context(self):
        return self._servlet_context

    def read_annotated_filter_name(self) -> str:
        if hasattr(filter.__class__, 'WebFilter'):
            annotation = getattr(filter.__class__, 'WebFilter')
            return annotation.name()
        else:
            return filter.__class__.__name__

    def read_annotated_init_params(self):
        init_params = {}
        if hasattr(filter.__class__, 'WebFilter'):
            annotation = getattr(filter.__class__, 'WebFilter')
            for param in annotation.initParams():
                init_params[param.name()] = param.value()
        return init_params

    @property
    def get_annotation(self) -> object:
        if hasattr(filter.__class__, 'WebFilter'):
            return filter.__class__.getAnnotation('WebFilter')
        else:
            return None


class Registration:
    def __init__(self, annotation):
        self.url_patterns = []
        self.dispatcher_types = set()
        self.async_supported = False

        for pattern in annotation.value():
            if not validate_mapping_path(pattern):
                raise ValueError(f"Invalid path mapping: {pattern}")
            self.url_patterns.append(pattern)

        for dispatcher_type in annotation.dispatcherTypes:
            self.dispatcher_types.add(dispatcher_type)
        self.async_supported = annotation.asyncSupported()

    def set_async_supported(self, value):
        self.async_supported = value

    @property
    def get_dispatcher_types(self) -> list:
        return list(self.dispatcher_types)


def validate_mapping_path(mapping: str) -> bool:
    parts = mapping.split('/')
    for i in range(len(parts)):
        if parts[i].strip() == '*':
            break
    else:
        return True

    return False


class Config:
    pass
```

Please note that Python does not have direct equivalent of Java's annotations. The code above uses the `hasattr` and `getattr` functions to check for the presence of a specific attribute on an object, which is similar in spirit to how you would use Java's annotations.