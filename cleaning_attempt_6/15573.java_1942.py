import numpy as np

class BatchNorm:
    def __init__(self):
        self.axis = 1
        self.epsilon = 1e-5
        self.momentum = .9
        self.center = True
        self.scale = True

        self.gamma = None
        self.beta = None
        self.running_mean = None
        self.running_var = None

    def forward(self, inputs):
        input_array = np.array(inputs)
        gamma_arr = self.get_gamma()
        beta_arr = self.get_beta()
        running_mean_arr = self.get_running_mean()
        running_var_arr = self.get_running_var()

        return batch_norm(input_array, running_mean_arr, running_var_arr, gamma_arr, beta_arr)

    def get_output_shapes(self):
        return [np.shape(inputs)[0] for inputs in np.split(np.array([]), 1)]

    def before_initialize(self, input_shapes):
        self.axis = len(input_shapes[0].shape) - 1
        self.in_channels = input_shapes[0].shape[self.axis]

    def prepare(self, input_shapes):
        if not hasattr(self, 'gamma'):
            self.gamma = np.random.rand(self.in_channels)
        if not hasattr(self, 'beta'):
            self.beta = np.zeros((self.in_channels,))
        if not hasattr(self, 'running_mean'):
            self.running_mean = np.zeros_like(self.gamma)
        if not hasattr(self, 'running_var'):
            self.running_var = np.ones_like(self.gamma)

    def save_metadata(self):
        pass

    @staticmethod
    def batch_norm(input_array, running_mean_arr, running_var_arr, gamma_arr=None, beta_arr=None):
        return input_array / (np.sqrt(running_var_arr) + 1e-5), gamma_arr * np.ones_like(input_array) + beta_arr


class Builder:
    def __init__(self):
        self.axis = 1
        self.epsilon = 1e-5
        self.momentum = .9
        self.center = True
        self.scale = True

    @property
    def axis(self):
        return self._axis

    @axis.setter
    def axis(self, value):
        self._axis = value

    @property
    def epsilon(self):
        return self._epsilon

    @epsilon.setter
    def epsilon(self, value):
        self._epsilon = value

    @property
    def momentum(self):
        return self._momentum

    @momentum.setter
    def momentum(self, value):
        self._momentum = value

    @property
    def center(self):
        return self._center

    @center.setter
    def center(self, value):
        self._center = bool(value)

    @property
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = bool(value)

    def build(self):
        batch_norm = BatchNorm()
        batch_norm.axis = self.axis
        batch_norm.epsilon = self.epsilon
        batch_norm.momentum = self.momentum
        batch_norm.center = self.center
        batch_norm.scale = self.scale

        return batch_norm


def main():
    builder = Builder().opt_axis(1).opt_center(True).opt_scale(False)
    model = builder.build()

if __name__ == "__main__":
    main()
