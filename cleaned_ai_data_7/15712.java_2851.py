class CosineTracker:
    def __init__(self, builder):
        self.base_value = builder.base_value
        self.final_value = builder.final_value
        self.max_updates = builder.max_updates

    @classmethod
    def builder(cls):
        return Builder()

    def get_new_value(self, num_update):
        if num_update > self.max_updates:
            return self.final_value
        step = (self.base_value - self.final_value) / 2 * (1 + math.cos(math.pi * num_update / self.max_updates))
        return self.final_value + step


class Builder:
    def __init__(self):
        self.base_value = None
        self.final_value = 0.01
        self.max_updates = None

    def set_base_value(self, base_value):
        self.base_value = base_value
        return self

    def opt_final_value(self, final_value):
        self.final_value = final_value
        return self

    def set_max_updates(self, max_updates):
        self.max_updates = max_updates
        return self

    def build(self):
        if not 0 < self.base_value:
            raise ValueError("You must set a starting learning rate!")
        if not isinstance(self.max_updates, int) or self.max_updates <= 0:
            raise ValueError("You must set a maximum number of updates!")
        if self.final_value >= self.base_value:
            raise ValueError("Starting learning rate must be greater than final learning rate!")
        return CosineTracker(self)
