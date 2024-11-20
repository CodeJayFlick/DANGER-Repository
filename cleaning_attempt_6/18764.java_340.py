class HttpClientBuilder:
    def __init__(self):
        self.uri = None
        self.authentication = None
        self.tracing = False
        self.read_timeout_millis = 25000
        self.connection_timeout_millis = 5000

    @staticmethod
    def builder():
        return HttpClientBuilder()

    def from_system_properties(self):
        return self.from_config(lambda x: os.environ.get(x))

    def from_config(self, config_function):
        uri_value = config_function(CONF_NESSIE_URI)
        if uri_value is not None:
            self.uri = URI(uri_value)

        with_authentication_from_config(config_function)

        tracing_value = config_function(CONF_NESSIE_TRACING)
        if tracing_value is not None:
            self.tracing = bool(tracing_value)

        return self

    def with_authentication_from_config(self, config_function):
        authentication_provider = NessieAuthenticationProvider.from_config(config_function)
        self.with_authentication(authentication_provider)
        return self

    def with_uri(self, uri):
        self.uri = URI(uri)
        return self

    def with_authentication(self, authentication):
        if authentication is not None and not isinstance(authentication, HttpAuthentication):
            raise ValueError("HttpClientBuilder only accepts instances of HttpAuthentication")
        self.authentication = authentication
        return self

    def with_tracing(self, tracing):
        self.tracing = tracing
        return self

    def with_read_timeout(self, read_timeout_millis):
        self.read_timeout_millis = read_timeout_millis
        return self

    def with_connection_timeout(self, connection_timeout_millis):
        self.connection_timeout_millis = connection_timeout_millis
        return self

    def build(self, api_version):
        if api_version is None:
            raise ValueError("API version class must be non-null")
        client = NessieHttpClient(
            uri=self.uri,
            authentication=self.authentication,
            tracing=self.tracing,
            read_timeout_millis=self.read_timeout_millis,
            connection_timeout_millis=self.connection_timeout_millis
        )
        if api_version == HttpApiV1:
            return HttpApiV1(client)
        else:
            raise ValueError(f"API version {api_version.__name__} is not supported.")
