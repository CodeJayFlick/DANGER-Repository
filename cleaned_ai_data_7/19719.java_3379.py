import math

class VectorLength:
    def __init__(self):
        pass

    @property
    def length(self):
        return lambda vector: vector.length()

    def change_mode(self, mode, delta):
        if mode in [1, 2]:  # ADD or REMOVE
            n = -delta[0] if mode == 2 else delta[0]
            v = self.get_vector()
            if math.sqrt(v.x**2 + v.y**2) < abs(n):  # check for overflow
                v.zero()
            elif mode == 1:
                l = n + math.sqrt(v.x**2 + v.y**2)
                v.normalize().multiply(l)
        else:  # SET
            if delta[0] < 0:
                self.get_vector().zero()
            else:
                self.get_vector().normalize().multiply(delta[0])

    def get_vector(self):
        return None

    @property
    def name(self):
        return "Vector Length"

    @property
    def description(self):
        return "Gets or sets the length of a vector."

    @property
    def examples(self):
        return ["send \"%standard length of vector 1, 2, 3%\"", 
                "set {_v} to vector 1, 2, 3", 
                "set standard length of {_v} to 2", 
                "send \"%%standard length of {_v}%\""]

    @property
    def since(self):
        return "2.2-Dev28"
