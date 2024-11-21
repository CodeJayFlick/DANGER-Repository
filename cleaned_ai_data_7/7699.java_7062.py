import matplotlib.colors as mcolors

class FcgVertexPaintTransformer:
    def __init__(self, color):
        self.color = color

    def apply(self, v):
        return self.color
