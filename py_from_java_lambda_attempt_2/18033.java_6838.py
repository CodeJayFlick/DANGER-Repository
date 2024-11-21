Here is the translation of the Java code to Python:
```
class RedirectException(Exception):
    def __init__(self, endpoint=None, device_endpoint_map=None):
        if endpoint:
            super().__init__("Later request in same group will be redirected to " + str(endpoint))
        elif device_endpoint_map:
            super().__init__("Later request in same group will be redirected to " + str(device_endpoint_map))
        else:
            raise ValueError("Both endpoint and device_endpoint_map cannot be None")

        self.end_point = endpoint
        self.device_end_point_map = device_endpoint_map

    @property
    def end_point(self):
        return self._end_point

    @end_point.setter
    def end_point(self, value):
        self._end_point = value

    @property
    def device_end_point_map(self):
        return self._device_end_point_map

    @device_end_point_map.setter
    def device_end_point_map(self, value):
        self._device_end_point_map = value
```
Note that I used the built-in `Exception` class in Python as a base for our custom exception. The constructor takes two optional arguments: `endpoint` and `device_endpoint_map`. If either of these is provided, it sets the corresponding attribute on the instance.

I also defined getter and setter properties for the attributes using Python's property decorator. This allows you to access the attributes like regular variables (e.g., `exception.end_point`) while still maintaining encapsulation.

Finally, I used a simple `raise ValueError` statement in the constructor if both `endpoint` and `device_endpoint_map` are None.