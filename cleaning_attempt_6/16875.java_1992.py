class IoTDBDataSource:
    def __init__(self):
        self.properties = Properties()

    def __init__(self, url, user, password, port=6667):
        self.url = url
        self.user = user
        self.password = password
        self.port = port if port != 0 else 6667
        self.properties = Properties()
        self.properties["user"] = user
        self.properties[password] = password

    @property
    def user(self):
        return self._user

    @user.setter
    def user(self, value):
        self._user = value
        self.properties["user"] = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value
        self.properties[password] = value

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        if value != 0:
            self._port = value

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        self._url = value

    def get_connection(self) -> Connection:
        try:
            from iotdb import IoTDBConnection
            return IoTDBConnection(self.url, self.properties)
        except Exception as e:
            print(str(e))

    def get_connection(self, username: str, password: str):
        try:
            new_prop = Properties()
            new_prop["user"] = username
            new_prop[password] = password
            from iotdb import IoTDBConnection
            return IoTDBConnection(self.url, new_prop)
        except Exception as e:
            print(str(e))

    def get_log_writer(self):
        pass

    def set_log_writer(self, writer: PrintWriter):
        pass

    def set_login_timeout(self, timeout: int):
        pass

    def get_login_timeout(self) -> int:
        return 0

    def parent_logger(self) -> Logger:
        pass

    def unwrap(self, a_class: Class['T']) -> 'T':
        pass

    def is_wrapper_for(self, a_class: Class) -> bool:
        return False
