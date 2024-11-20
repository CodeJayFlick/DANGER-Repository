class PolynomialDecayTracker:
    def __init__(self, builder):
        if not isinstance(builder.end_learning_rate, (int, float)) or builder.end_learning_rate == float('nan'):
            raise ValueError("End learning rate is not set.")
        if builder.decay_steps <= 0:
            raise ValueError("Decay steps is not set.")

        self.base_value = builder.base_value
        self.end_learning_rate = builder.end_learning_rate
        self.decay_steps = builder.decay_steps
        self.power = builder.power

    def get_new_value(self, num_update):
        step = max(0, min(num_update, self.decay_steps))
        return (self.base_value - self.end_learning_rate) * ((1.0 - step / self.decay_steps)**self.power) + self.end_learning_rate


class Builder:
    def __init__(self):
        pass

    @property
    def base_value(self):
        raise AttributeError("Base value is not set.")

    @base_value.setter
    def base_value(self, value):
        self._base_value = value

    @property
    def end_learning_rate(self):
        return self._end_learning_rate

    @end_learning_rate.setter
    def end_learning_rate(self, value):
        if isinstance(value, (int, float)):
            self._end_learning_rate = value
        else:
            raise ValueError("End learning rate is not set.")

    @property
    def decay_steps(self):
        return self._decay_steps

    @decay_steps.setter
    def decay_steps(self, value):
        if isinstance(value, int) and value > 0:
            self._decay_steps = value
        else:
            raise ValueError("Decay steps is not set.")

    @property
    def power(self):
        return self._power

    @power.setter
    def power(self, value):
        self._power = value


def builder():
    return Builder()
