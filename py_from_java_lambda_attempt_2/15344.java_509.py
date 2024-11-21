Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the `Activity` class and its usage in Java. In Python, we don't have a direct equivalent of Android's Activity class, so I replaced it with an abstract property (`activity`) that can be set later.

Also, I didn't translate the `RequestNetworkController` class as it seems to be specific to your application and may require additional context or implementation details.