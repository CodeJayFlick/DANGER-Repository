import math

class BlockLineIterator:
    def __init__(self, start_block=None, end_block=None):
        if isinstance(start_block, tuple) or (isinstance(start_block, dict) and 'x' in start_block and 'y' in start_block and 'z' in start_block):
            self.start = Location(*start_block)
        else:
            self.start = start_block

        if isinstance(end_block, tuple) or (isinstance(end_block, dict) and 'x' in end_block and 'y' in end_block and 'z' in end_block):
            self.end = Location(*end_block)
        else:
            self.end = end_block

    def __iter__(self):
        if isinstance(self.start, tuple) or (isinstance(self.start, dict) and 'x' in self.start and 'y' in self.start and 'z' in self.start):
            start_vector = Vector(*self.start)
        else:
            start_vector = self.start.toVector()

        if isinstance(self.end, tuple) or (isinstance(self.end, dict) and 'x' in self.end and 'y' in self.end and 'z' in self.end):
            end_vector = Vector(*self.end)
        else:
            end_vector = self.end.toVector()

        for block in BlockIterator(self.start.getWorld(), start_vector.add(0.5, 0.5, 0.5), end_vector.subtract(start_vector).toVector()):
            yield block

    def __init__(self, start_location=None, direction_vector=None, distance=0):
        if isinstance(start_location, tuple) or (isinstance(start_location, dict) and 'x' in start_location and 'y' in start_location and 'z' in start_location):
            self.start = Location(*start_location)
        else:
            self.start = start_location

        if direction_vector is None:
            raise ValueError("Direction vector cannot be null")
        elif isinstance(direction_vector, tuple) or (isinstance(direction_vector, dict) and 'x' in direction_vector and 'y' in direction_vector and 'z' in direction_vector):
            self.direction = Vector(*direction_vector)
        else:
            self.direction = direction_vector

        if distance < 0:
            raise ValueError("Distance cannot be negative")
        elif isinstance(distance, int):
            self.distance = float(distance)
        else:
            self.distance = distance

    def __iter__(self):
        for block in BlockIterator(self.start.getWorld(), fit_in_world(self.start.add(0.5, 0.5, 0.5), self.direction)):
            yield block


def fit_in_world(location=None, direction_vector=None):
    if location is None:
        raise ValueError("Location cannot be null")
    elif isinstance(location, tuple) or (isinstance(location, dict) and 'x' in location and 'y' in location and 'z' in location):
        x, y, z = location
    else:
        x, y, z = location.get_x(), location.get_y(), location.get_z()

    if direction_vector is None:
        raise ValueError("Direction vector cannot be null")
    elif isinstance(direction_vector, tuple) or (isinstance(direction_vector, dict) and 'x' in direction_vector and 'y' in direction_vector and 'z' in direction_vector):
        dx, dy, dz = direction_vector
    else:
        dx, dy, dz = direction_vector.get_x(), direction_vector.get_y(), direction_vector.get_z()

    if abs(dy) < 1e-6:  # Skript.EPSILON is equivalent to 1e-6 in Python
        return x, y, z

    dy = (y - location.get_y()) / dy
    return x + dx * dy, y + dy, z + dz * dy


class Location:
    def __init__(self, world=None, vector=None):
        self.world = world
        if isinstance(vector, tuple) or (isinstance(vector, dict) and 'x' in vector and 'y' in vector and 'z' in vector):
            x, y, z = vector
        else:
            x, y, z = vector.get_x(), vector.get_y(), vector.get_z()
        self.vector = Vector(x, y, z)

    def get_world(self):
        return self.world

    def toVector(self):
        return self.vector


class BlockIterator:
    def __init__(self, world=None, direction_vector=None, start_vector=None, end_x=0, end_y=0):
        if isinstance(world, tuple) or (isinstance(world, dict) and 'x' in world and 'y' in world and 'z' in world):
            self.world = Location(*world)
        else:
            self.world = world

        if direction_vector is None:
            raise ValueError("Direction vector cannot be null")
        elif isinstance(direction_vector, tuple) or (isinstance(direction_vector, dict) and 'x' in direction_vector and 'y' in direction_vector and 'z' in direction_vector):
            dx, dy, dz = direction_vector
        else:
            dx, dy, dz = direction_vector.get_x(), direction_vector.get_y(), direction_vector.get_z()

        self.direction_vector = Vector(dx, dy, dz)

        if start_vector is None:
            raise ValueError("Start vector cannot be null")
        elif isinstance(start_vector, tuple) or (isinstance(start_vector, dict) and 'x' in start_vector and 'y' in start_vector and 'z' in start_vector):
            sx, sy, sz = start_vector
        else:
            sx, sy, sz = start_vector.get_x(), start_vector.get_y(), start_vector.get_z()

        self.start_vector = Vector(sx, sy, sz)

    def __iter__(self):
        for block in BlockIterator(self.world.getWorld(), self.direction_vector.add(0.5, 0.5, 0.5), self.start_vector.subtract(self.direction_vector).toVector()):
            yield block


class Vector:
    def __init__(self, x=0, y=0, z=0):
        self.x = float(x)
        self.y = float(y)
        self.z = float(z)

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y

    def get_z(self):
        return self.z

    def toVector(self):
        return Vector(self.x, self.y, self.z)


class Location:
    pass


class BlockIterator:
    pass
