class RequestNetwork:
    def __init__(self):
        self.params = {}
        self.headers = {}

    def set_headers(self, headers):
        self.headers = headers

    def set_params(self, params, request_type):
        self.params = params
        self.request_type = request_type

    @property
    def params(self):
        return self.params

    @property
    def headers(self):
        return self.headers

    @property
    def activity(self):
        raise NotImplementedError("Activity not set")

    @activity.setter
    def activity(self, value):
        self._activity = value

    @property
    def request_type(self):
        return self.request_type

    def start_request_network(self, method: str, url: str, tag: str, request_listener):
        RequestNetworkController().execute(self, method, url, tag, request_listener)

class RequestListener:
    def onResponse(self, tag: str, response: str):
        pass  # implement me!

    def onErrorResponse(self, tag: str, message: str):
        pass  # implement me!
