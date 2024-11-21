class Direction:
    ZERO = None  # A direction that doesn't point anywhere.
    IDENTITY = None  # A direction that points in the direction of the object(s) passed.

    BF_X = None
    BF_Y = None
    BF_Z = None

    def __init__(self, mod=None):
        if mod is not None:
            self.pitchOrX = mod[0]
            self.yawOrY = mod[1]
            self.lengthOrZ = mod[2]

    @staticmethod
    def pitch_to_radians(pitch):
        return -math.radians(pitch)

    @staticmethod
    def yaw_to_radians(yaw):
        return math.radians(yaw) + math.pi / 2

    @classmethod
    def get_facing(cls, block_face):
        if isinstance(block_face, BlockFace):
            return block_face.get_mod_x(), block_face.get_mod_y(), block_face.get_mod_z()
        else:
            return None

    @staticmethod
    def combine(dirs, locs):
        class CombinedExpression(Expression[Location]):
            def __init__(self, dirs, locs):
                self.dirs = dirs
                self.locs = locs

            def get(self, event=None):
                if isinstance(event, Event):
                    return [d.get_relative(loc) for d in dirs.get_array(event) for loc in self.locs.get_array(event)]
                else:
                    return []

        return CombinedExpression(dirs, locs)

    @staticmethod
    def deserialize(s):
        parts = s.split(":")
        if len(parts) != 2:
            return None

        relative = bool(int(parts[0]))
        mod = [float(x) for x in parts[1].split(",")]
        if len(mod) == 3:
            return Direction(mod)
        else:
            return None
