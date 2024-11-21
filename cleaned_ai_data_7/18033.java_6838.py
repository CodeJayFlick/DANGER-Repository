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
