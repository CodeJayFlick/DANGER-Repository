class Message:
    def __init__(self):
        self.device = None
        self.timestamp = None
        self.measurements = []
        self.values = []

    @property
    def device(self):
        return self._device

    @device.setter
    def device(self, value):
        self._device = value

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value

    @property
    def measurements(self):
        return self._measurements

    @measurements.setter
    def measurements(self, value):
        if not isinstance(value, list):
            raise TypeError("Measurements must be a list")
        self._measurements = value

    @property
    def values(self):
        return self._values

    @values.setter
    def values(self, value):
        if not isinstance(value, list):
            raise TypeError("Values must be a list")
        self._values = value

    def __str__(self):
        return f"Message{{'device': '{self.device}', 'timestamp': {self.timestamp}, 'measurements': {self.measurements}, 'values': {self.values}}}"
