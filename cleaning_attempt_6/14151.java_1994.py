class PlayMessage:
    def __init__(self, stream: 'AudioInputStream', volume=1.0):
        self.stream = stream
        self.volume = volume

    @property
    def volume(self):
        return self._volume

    @volume.setter
    def volume(self, value):
        if not isinstance(value, float) or value < 0:
            raise ValueError("Volume must be a non-negative number")
        self._volume = value


class AudioInputStream:  # Assuming this is an existing class in Python
    pass
