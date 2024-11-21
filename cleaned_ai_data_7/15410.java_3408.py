class MultiBoxPrior:
    def __init__(self, sizes: list[float], ratios: list[float], steps: list[float], offsets: list[float], clip: bool):
        self.sizes = sizes
        self.ratios = ratios
        self.steps = steps
        self.offsets = offsets
        self.clip = clip

    def generate_anchor_boxes(self, input_array) -> 'NDArray':
        return input_array.multi_box_prior(self.sizes, self.ratios, self.steps, self.offsets, self.clip).head()

class Builder:
    def __init__(self):
        self.sizes: list[float] = [1.0]
        self.ratios: list[float] = [1.0]
        self.steps: list[float] = [-1.0, -1.0]
        self.offsets: list[float] = [0.5, 0.5]
        self.clip: bool = False

    def set_sizes(self, sizes: list[float]) -> 'Builder':
        self.sizes = sizes
        return self

    def set_ratios(self, ratios: list[float]) -> 'Builder':
        self.ratios = ratios
        return self

    def opt_steps(self, steps: list[float]) -> 'Builder':
        self.steps = steps
        return self

    def opt_offsets(self, offsets: list[float]) -> 'Builder':
        self.offsets = offsets
        return self

    def opt_clip(self, clip: bool) -> 'Builder':
        self.clip = clip
        return self

    def build(self) -> MultiBoxPrior:
        return MultiBoxPrior(self.sizes, self.ratios, self.steps, self.offsets, self.clip)
