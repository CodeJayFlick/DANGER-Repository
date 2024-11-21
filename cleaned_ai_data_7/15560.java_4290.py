class Conv2DTranspose:
    def __init__(self):
        pass

def conv2d_transpose(input_array: list, weight_array: list, bias_array=None) -> list:
    return [convolve_2d_deformable(input_array, weight_array, bias_array)]

def convolve_2d_deformable(input_array: list, weight_array: list, bias_array=None):
    # implement the 2D deconvolution operation
    pass

class Builder:
    def __init__(self):
        self.stride = [1, 1]
        self.padding = [[0, 0], [0, 0]]
        self.out_padding = [[0, 0], [0, 0]]
        self.dilation = [1, 1]

    @property
    def stride(self) -> list:
        return self._stride

    @stride.setter
    def stride(self, value: list):
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ValueError("Stride must be a list of length 2")
        self._stride = value

    @property
    def padding(self) -> list:
        return self._padding

    @padding.setter
    def padding(self, value: list):
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ValueError("Padding must be a list of length 2")
        for i in range(2):
            if not all(isinstance(x, int) for x in value[i]):
                raise ValueError(f"Padding {i} must contain only integers")
        self._padding = value

    @property
    def out_padding(self) -> list:
        return self._out_padding

    @out_padding.setter
    def out_padding(self, value: list):
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ValueError("Out padding must be a list of length 2")
        for i in range(2):
            if not all(isinstance(x, int) for x in value[i]):
                raise ValueError(f"Out padding {i} must contain only integers")
        self._out_padding = value

    @property
    def dilation(self) -> list:
        return self._dilation

    @dilation.setter
    def dilation(self, value: list):
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ValueError("Dilation must be a list of length 2")
        for i in range(2):
            if not all(isinstance(x, int) for x in value[i]):
                raise ValueError(f"Dilation {i} must contain only integers")
        self._dilation = value

    def build(self) -> Conv2DTranspose:
        return Conv2DTranspose()
