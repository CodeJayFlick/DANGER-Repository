class SpaceQuality:
    def __init__(self, name):
        self.name = name
        self.type = 'ram_space'
        self.size = 0
        self.wordsize = 1
        self.isdefault = False

    def __str__(self):
        return f"sq:{{name={self.name}, type={self.type}, size={self.size}, wordsize={self.wordsize}, isdefault={self.isdefault}}}"
