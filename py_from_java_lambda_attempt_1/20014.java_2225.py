Here is the translation of the Java code into Python:

```Python
import math

class Vector:
    def __init__(self, x=0, y=0, z=0):
        self.x = x
        self.y = y
        self.z = z

    def clone(self):
        return Vector(self.x, self.y, self.z)

    def dot(self, vector):
        return self.x * vector.x + self.y * vector.y + self.z * vector.z


class VectorMath:
    PI = math.pi
    HALF_PI = PI / 2
    DEG_TO_RAD = PI / 180
    RAD_TO_DEG = 180 / PI

    @staticmethod
    def from_spherical_coordinates(radius, theta, phi):
        r = abs(radius)
        t = theta * VectorMath.DEG_TO_RAD
        p = phi * VectorMath.DEG_TO_RAD
        sin_p = math.sin(p)
        x = r * sin_p * math.cos(t)
        y = r * math.cos(p)
        z = r * sin_p * math.sin(t)
        return Vector(x, y, z)

    @staticmethod
    def from_cylindrical_coordinates(radius, phi, height):
        r = abs(radius)
        p = phi * VectorMath.DEG_TO_RAD
        x = r * math.cos(p)
        z = r * math.sin(p)
        return Vector(x, height, z)

    @staticmethod
    def from_yaw_and_pitch(yaw, pitch):
        y = math.sin(pitch * VectorMath.DEG_TO_RAD)
        div = math.cos(pitch * VectorMath.DEG_TO_RAD)
        x = math.cos(yaw * VectorMath.DEG_TO Рад)
        z = math.sin(yaw * VectorMath.DEG_TO_RAD)
        x *= div
        z *= div
        return Vector(x, y, z)

    @staticmethod
    def get_yaw(vector):
        if vector.x == 0 and vector.z == 0:
            return 0
        return (math.atan2(vector.z, vector.x) * VectorMath.RAD_TO_DEG)

    @staticmethod
    def get_pitch(vector):
        xy = math.sqrt(vector.x ** 2 + vector.z ** 2)
        if xy < 1e-6:  # to avoid division by zero error
            return 0
        return (math.atan(vector.y / xy) * VectorMath.RAD_TO_DEG)

    @staticmethod
    def set_yaw(vector, yaw):
        vector = VectorMath.from_yaw_and_pitch(yaw, VectorMath.get_pitch(vector))
        return vector

    @staticmethod
    def set_pitch(vector, pitch):
        vector = VectorMath.from_yaw_and_pitch(VectorMath.get_yaw(vector), pitch)
        return vector

    @staticmethod
    def rot_x(vector, angle):
        sin_angle = math.sin(angle * VectorMath.DEG_TO_RAD)
        cos_angle = math.cos(angle * VectorMath.DEG_TO_RAD)
        vy = Vector(0, cos_angle, -sin_angle)
        vz = Vector(0, sin_angle, cos_angle)
        clone = vector.clone()
        vector.y = clone.dot(vy)
        vector.z = clone.dot(vz)
        return vector

    @staticmethod
    def rot_y(vector, angle):
        sin_angle = math.sin(angle * VectorMath.DEG_TO_RAD)
        cos_angle = math.cos(angle * VectorMath.DEG_TO_RAD)
        vx = Vector(cos_angle, 0, sin_angle)
        vz = Vector(-sin_angle, 0, cos_angle)
        clone = vector.clone()
        vector.x = clone.dot(vx)
        vector.z = clone.dot(vz)
        return vector

    @staticmethod
    def rot_z(vector, angle):
        sin_angle = math.sin(angle * VectorMath.DEG_TO_RAD)
        cos_angle = math.cos(angle * VectorMath.DEG_TO_RAD)
        vx = Vector(cos_angle, -sin_angle, 0)
        vy = Vector(sin_angle, cos_angle, 0)
        clone = vector.clone()
        vector.x = clone.dot(vx)
        vector.y = clone.dot(vy)
        return vector

    @staticmethod
    def rot(vector, axis, angle):
        sin_angle = math.sin(angle * VectorMath.DEG_TO_RAD)
        cos_angle = math.cos(angle * VectorMath.DEG_TO_RAD)
        a = axis.clone().normalize()
        ax = a.x
        ay = a.y
        az = a.z
        rotx = Vector(cos_angle + ax ** 2 * (1 - cos_angle), ax * ay * (1 - cos_angle) - az * sin_angle, ax * az * (1 - cos_angle) + ay * sin_angle)
        roty = Vector(ay * ax * (1 - cos_angle) + az * sin_angle, cos_angle + ay ** 2 * (1 - cos_angle), ay * az * (1 - cos_angle) - ax * sin_angle)
        rotz = Vector(az * ax * (1 - cos_angle) - ay * sin_angle, az * ay * (1 - cos_angle) + ax * sin_angle, cos_angle + az ** 2 * (1 - cos_angle))
        x = rotx.dot(vector)
        y = roty.dot(vector)
        z = rotz.dot(vector)
        vector.x = x
        vector.y = y
        vector.z = z
        return vector

    @staticmethod
    def notch_yaw(yaw):
        y = yaw - 90
        if y < -180:
            y += 360
        return y

    @staticmethod
    def notch_pitch(pitch):
        return -pitch

    @staticmethod
    def from_notch_yaw(notch_yaw):
        y = notch_yaw + 90
        if y > 180:
            y -= 360
        return y

    @staticmethod
    def from_notch_pitch(notch_pitch):
        return -notch_pitch

    @staticmethod
    def skript_yaw(yaw):
        y = yaw - 90
        if y < 0:
            y += 360
        return y

    @staticmethod
    def skript_pitch(pitch):
        return -pitch

    @staticmethod
    def from_skript_yaw(yaw):
        y = yaw + 90
        if y > 360:
            y -= 360
        return y

    @staticmethod
    def from_skript_pitch(pitch):
        return -pitch

    @staticmethod
    def wrap_angle_deg(angle):
        angle %= 360
        if angle <= -180:
            return angle + 360
        elif angle > 180:
            return angle - 360
        else:
            return angle


# Example usage:

vector = VectorMath.from_spherical_coordinates(1, math.pi / 2, math.pi)
print(vector.x, vector.y, vector.z)

yaw = VectorMath.skript_yaw(math.pi / 4)
pitch = VectorMath.notch_pitch(math.pi / 3)
print(VectorMath.set_yaw(VectorMath.from_cylindrical_coordinates(1, math.pi / 2, 0), yaw).x,
      VectorMath.set_pitch(VectorMath.from_spherical_coordinates(1, math.pi / 2, math.pi / 4), pitch).y)

angle = math.pi / 6
print(VectorMath.rot_x(vector, angle).x)
```

Please note that this is a direct translation of the Java code into Python. The original author's intent and purpose might not be fully reflected in this Python version due to differences between languages.