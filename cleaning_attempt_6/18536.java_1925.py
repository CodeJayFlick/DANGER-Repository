class AwsServletRegistration:
    def __init__(self, name: str, servlet: object, ctx: 'AwsServletContext') -> None:
        self.servlet_name = name
        self.servlet = servlet
        self.ctx = ctx
        self.init_parameters = {}
        self.load_on_startup = -1
        self.run_as_role = ''
        self.async_supported = True

    def add_mapping(self, *strings) -> set:
        failed_mappings = set()
        for s in strings:
            if s in self.servlet_path_mappings:
                failed_mappings.add(s)
                continue
            self.servlet_path_mappings[s] = self
        return failed_mappings

    @property
    def servlet_path_mappings(self):
        return {}

    def get_mappings(self) -> collection:
        return set(self.servlet_path_mappings.keys())

    @property
    def run_as_role(self):
        return self._run_as_role

    @run_as_role.setter
    def run_as_role(self, value: str):
        self._run_as_role = value

    @property
    def name(self) -> str:
        return self.servlet_name

    @property
    def class_name(self) -> str:
        return type(self.servlet).__name__

    def set_init_parameter(self, key: str, value: str) -> bool:
        if key in self.init_parameters:
            return False
        self.init_parameters[key] = value
        return True

    def get_init_parameter(self, key: str) -> str | None:
        return self.init_parameters.get(key)

    def set_init_parameters(self, parameters: dict) -> set:
        failed_parameters = set()
        for param in parameters.items():
            if key in self.init_parameters:
                failed_parameters.add(param[0])
            self.init_parameters[param[0]] = param[1]
        return failed_parameters

    @property
    def init_parameters(self):
        return self._init_parameters

    @init_parameters.setter
    def init_parameters(self, value: dict):
        self._init_parameters = value

    def get_init_parameters(self) -> dict:
        return self.init_parameters.copy()

    @property
    def servlet(self):
        return self._servlet

    @servlet.setter
    def servlet(self, value: object):
        self._servlet = value

    def set_load_on_startup(self, load_on_startup: int) -> None:
        self.load_on_startup = load_on_startup

    @property
    def load_on_startup(self) -> int:
        return self._load_on_startup

    @load_on_startup.setter
    def load_on_startup(self, value: int):
        self._load_on_startup = value

    def set_servlet_security(self, servlet_security_element: object) -> set:
        return set()

    def set_multipart_config(self, multipart_config_element: object) -> None:
        pass

    @property
    def async_supported(self) -> bool:
        return self._async_supported

    @async_supported.setter
    def async_supported(self, value: bool):
        self._async_supported = value

    def compare_to(self, other: 'AwsServletRegistration') -> int:
        if not isinstance(other, AwsServletRegistration):
            raise TypeError("Other must be an instance of AwsServletRegistration")
        return (self.load_on_startup - other.load_on_startup)

    @property
    def equals(self) -> bool | None:
        pass

    def is_async_supported(self) -> bool:
        return self.async_supported

    def get_servlet_config(self) -> object:
        return ServletConfig(
            servlet_name=self.servlet_name,
            servlet_context=self.ctx,
            init_parameters=self.init_parameters
        )


class AwsServletContext:
    # Implementation of the interface


class ServletRegistration:
    pass


class ServletSecurityElement:
    pass


class MultipartConfigElement:
    pass


class ServletConfig:
    def __init__(self, servlet_name: str, servlet_context: 'AwsServletContext', init_parameters: dict) -> None:
        self.servlet_name = servlet_name
        self.servlet_context = servlet_context
        self.init_parameters = init_parameters

    @property
    def get_servlet_name(self):
        return self.servlet_name

    @get_servlet_name.setter
    def set_servlet_name(self, value: str):
        self.servlet_name = value

    @property
    def get_servlet_context(self) -> 'AwsServletContext':
        return self.servlet_context

    @get_servlet_context.setter
    def set_servlet_context(self, value: object):
        if not isinstance(value, AwsServletContext):
            raise TypeError("Value must be an instance of AwsServletContext")
        self.servlet_context = value

    @property
    def get_init_parameter(self, key: str) -> str | None:
        return self.init_parameters.get(key)

    @get_init_parameter.setter
    def set_init_parameter(self, key: str, value: str):
        if not isinstance(value, str):
            raise TypeError("Value must be a string")
        self.init_parameters[key] = value

    @property
    def get_init_parameter_names(self) -> collection:
        return iter(self.init_parameters.keys())
