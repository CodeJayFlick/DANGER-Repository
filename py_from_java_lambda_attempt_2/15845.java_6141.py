Here is the translation of the Java code into Python:

```Python
class DynamicBuffer:
    def __init__(self):
        self.buffer = bytearray(128)
        self.length = 0

    def put(self, f: float) -> 'DynamicBuffer':
        self.length += 1
        if len(self.buffer) == self.length * 2:
            new_buffer = bytearray(len(self.buffer) * 2)
            new_buffer[:len(self.buffer)] = self.buffer[:]
            self.buffer = new_buffer
        buffer_array = array('f', [0.0] + list(self.buffer))
        buffer_array[self.length - 1] = f
        self.buffer = memoryview(buffer_array).tobytes()[:-4]
        return self

    def getBuffer(self) -> bytearray:
        return self.buffer[:self.length]

    def getLength(self) -> int:
        return self.length


import array
```

Please note that Python does not have a direct equivalent of Java's FloatBuffer. The above code uses the `array` and `bytearray` modules to simulate similar functionality.