Here is the translation of the given Java code into Python:

```Python
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
```

Please note that the `AudioInputStream` class does not exist in standard Python libraries. You would need to implement it yourself or use some external library if you're working with audio streams.

Also, I used a property for the volume attribute and added validation on setting the value to ensure it's always non-negative.