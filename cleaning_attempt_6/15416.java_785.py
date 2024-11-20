class Mask:
    def __init__(self, x: float, y: float, width: float, height: float, prob_dist):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.prob_dist = prob_dist

    @property
    def get_prob_dist(self) -> list:
        return self.prob_dist


# Example usage:

prob_dist = [[0.1, 0.2], [0.3, 0.4]]
mask = Mask(10.5, 20.7, 30.9, 40.8, prob_dist)
print(mask.get_prob_dist)  # Output: [[0.1, 0.2], [0.3, 0.4]]
