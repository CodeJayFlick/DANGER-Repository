class HttpApiV2HttpContext:
    def __init__(self):
        self.method = None
        self.path = None
        self.protocol = None
        self.source_ip = None
        self.user_agent = None

    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, value):
        self._method = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        self._protocol = value

    @property
    def source_ip(self):
        return self._source_ip

    @source_ip.setter
    def source_ip(self, value):
        self._source_ip = value

    @property
    def user_agent(self):
        return self._user_agent

    @user_agent.setter
    def user_agent(self, value):
        self._user_agent = value
