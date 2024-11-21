class AABB:
    def __init__(self, l1: 'Location', l2: 'Location'):
        if l1.world != l2.world:
            raise ValueError("Locations must be in the same world")
        self.world = l1.world
        self.lower_bound = Vector(min(l1.x, l2.x), min(l1.y, l2.y), min(l1.z, l2.z))
        self.upper_bound = Vector(max(l1.x, l2.x), max(l1.y, l2.y), max(l1.z, l2.z))

    def __init__(self, b1: 'Block', b2: 'Block'):
        if b1.world != b2.world:
            raise ValueError("Blocks must be in the same world")
        self.world = b1.world
        self.lower_bound = Vector(min(b1.x, b2.x), min(b1.y, b2.y), min(b1.z, b2.z))
        self.upper_bound = Vector(max(b1.x, b2.x), max(b1.y, b2.y), max(b1.z, b2.z))

    def __init__(self, center: 'Location', r_x: float, r_y: float, r_z: float):
        assert all([r_x >= 0, r_y >= 0, r_z >= 0]), f"rX={r_x}, rY={r_y}, rZ={r_z}"
        self.world = center.world
        self.lower_bound = Vector(center.x - r_x, max(0, center.y - r_y), center.z - r_z)
        self.upper_bound = Vector(center.x + r_x, min(self.world.max_height - 1, center.y + r_y), center.z + r_z)

    def __init__(self, w: 'World', v1: 'Vector', v2: 'Vector'):
        self.world = w
        self.lower_bound = Vector(min(v1.x, v2.x), min(v1.y, v2.y), min(v1.z, v2.z))
        self.upper_bound = Vector(max(v1.x, v2.x), max(v1.y, v2.y), max(v1.z, v2.z))

    def __init__(self, c: 'Chunk'):
        self.world = c.world
        self.lower_bound = c.blocks[0][0].location.to_vector()
        self.upper_bound = Vector(15, self.world.max_height - 1, 15)

    def contains(self, l: 'Location') -> bool:
        if l.world != self.world:
            return False
        return all([l.x + 1e-6 < self.lower_bound.x,
                    self.lower_bound.x <= l.x,
                    l.y + 1e-6 < self.lower_bound.y,
                    self.lower_bound.y <= l.y,
                    l.z + 1e-6 < self.lower_bound.z,
                    self.lower_bound.z <= l.z])

    def contains(self, b: 'Block') -> bool:
        return self.contains(b.location) and self.contains(Vector(1, 1, 1).add(b.location))

    def get_dimensions(self):
        return (self.upper_bound - self.lower_bound)

    def get_world(self):
        return self.world

    class Iterator:
        def __init__(self):
            self.min_x = math.ceil((self.lower_bound.x + 1e-6))
            self.max_x = math.floor((self.upper_bound.x - 1e-6))
            self.min_y = math.ceil((self.lower_bound.y + 1e-6))
            self.max_y = math.floor((self.upper_bound.y - 1e-6))
            self.min_z = math.ceil((self.lower_bound.z + 1e-6))
            self.max_z = math.floor((self.upper_bound.z - 1e-6))

        def __iter__(self):
            return self

        def __next__(self):
            if not hasattr(self, 'x'):
                raise StopIteration
            x += 1
            if x > self.max_x:
                x = self.min_x
                z += 1
                if z > self.max_z:
                    y += 1
                    return world.get_block_at(x, y, z)
            return next(self)

        def __iter__(self):
            return self

    def __hash__(self) -> int:
        result = hash((self.lower_bound.x, self.upper_bound.x,
                       self.lower_bound.y, self.upper_bound.y,
                       self.lower_bound.z, self.upper_bound.z))
        return result

    def __eq__(self, other: 'AABB') -> bool:
        if not isinstance(other, AABB):
            return False
        return (self.lower_bound == other.lower_bound and 
                self.upper_bound == other.upper_bound and 
                self.world == other.world)
