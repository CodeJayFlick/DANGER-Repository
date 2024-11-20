import numpy as np

class MinMaxScaler:
    def __init__(self):
        self.fitted_min = None
        self.fitted_max = None
        self.fitted_range = None
        self.min_range = 0.0
        self.max_range = 1.0
        self.detached = False

    def fit(self, data, axes=None):
        if axes is not None:
            self.fitted_min = np.min(data, axis=axes)
            self.fitted_max = np.max(data, axis=axes)
            self.fitted_range = self.fitted_max - self.fitted_min
        else:
            self.fitted_min = np.min(data)
            self.fitted_max = np.max(data)
            self.fitted_range = self.fitted_max - self.fitted_min

    def transform(self, data):
        if self.fitted_range is None:
            self.fit(data)

        std = (data - self.fitted_min) / self.fitted_range
        return scale(std)

    def inverse_transform(self, data):
        if not hasattr(self, 'fitted_range'):
            raise ValueError("Min Max Scaler is not fitted")

        result = inverse_scale(data)
        return result * self.fitted_range + self.fitted_min

    def detach(self):
        self.detached = True
        if hasattr(self, 'fitted_min') and self.fitted_min is not None:
            self.fitted_min.detach()
        if hasattr(self, 'fitted_max') and self.fitted_max is not None:
            self.fitted_max.detach()
        if hasattr(self, 'fitted_range') and self.fitted_range is not None:
            self.fitted_range.detach()

    def set_opt_range(self, min_range=0.0, max_range=1.0):
        self.min_range = min_range
        self.max_range = max_range

    @property
    def min_(self):
        if hasattr(self, 'fitted_min') and self.fitted_min is not None:
            return self.fitted_min
        else:
            raise ValueError("Min Max Scaler is not fitted")

    @property
    def max_(self):
        if hasattr(self, 'fitted_max') and self.fitted_max is not None:
            return self.fitted_max
        else:
            raise ValueError("Min Max Scaler is not fitted")


def scale(std):
    if std.min() != 0.0 or std.max() - std.min() != 1.0:
        return (std - std.min()) * (MinMaxScaler().max_range - MinMaxScaler().min_range) + MinMaxScaler().min_range
    else:
        return std


def inverse_scale(std):
    if std.min() != 0.0 or std.max() - std.min() != 1.0:
        return (std - MinMaxScaler().min_range) / (MinMaxScaler().max_range - MinMaxScaler().min_range)
    else:
        return std
