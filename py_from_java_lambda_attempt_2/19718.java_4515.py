Here is a translation of the Java code into equivalent Python:

```Python
class VectorFromYawAndPitch:
    def __init__(self):
        self.pitch = None
        self.yaw = None

    @staticmethod
    def register_expression():
        pass  # This method doesn't have an exact equivalent in Python.

    def init(self, exprs):
        if len(exprs) != 2:
            return False
        self.pitch = exprs[0]
        self.yaw = exprs[1]
        return True

    def get(self):
        yaw_value = self.yaw.get()
        pitch_value = self.pitch.get()
        if yaw_value is None or pitch_value is None:
            return []
        yaw_angle = VectorMath.from_skript_yaw(VectorMath.wrap_angle_deg(yaw_value))
        pitch_angle = VectorMath.from_skript_pitch(VectorMath.wrap_angle_deg(pitch_value))
        return [VectorMath.from_yaw_and_pitch(yaw_angle, pitch_angle)]

    def is_single(self):
        return True

    def get_return_type(self):
        from vector import Vector
        return Vector

    def __str__(self):
        return f"vector from yaw {self.yaw} and pitch {self.pitch}"
```

Please note that Python does not have an exact equivalent to Java's static initialization block. The `register_expression` method is removed in the translation, as it doesn't have a direct equivalent in Python.

Also, Python's type system is dynamic, so there is no need for explicit null checks like in Java.