Here is the translation of the given Java code into Python:

```Python
import numpy as np

class TestData:
    def __init__(self):
        self.filters = 0
        self.height = 0
        self.width = 0
        self.kernel = None
        self.padding = None
        self.stride = None
        self.dilation = None

def test_output_shapes():
    filters_range = range(1, 4)
    heights_range = range(1, 4)
    widths_range = range(1, 4)

    kernel_height_range = range(1, 4)
    kernel_width_range = range(1, 4)

    padding_height_range = range(0, 4)
    padding_width_range = range(0, 4)

    stride_height_range = range(1, 4)
    stride_width_range = range(1, 4)

    dilation_height_range = range(1, 4)
    dilation_width_range = range(1, 4)

    rows = len(filters_range) * len(heights_range) * len(widths_range) * len(kernel_height_range) * len(kernel_width_range) * len(padding_height_range) * len(padding_width_range) * len(stride_height_range) * len(stride_width_range) * len(dilation_height_range) * len(dilation_width_range)

    if bool("nightly"):  # During nightly testing, test all rows
        stream_to_test = range(0, int(rows))
    else:  # During unit testing, only test the first and last
        stream_to_test = [0, int(rows)-1]

    for i in stream_to_test:
        data = TestData()
        index = i

        filters_option = (index % len(filters_range),) + ((i // len(filters_range)) % len(heights_range),) + ((i // (len(filters_range)*len(heights_range))) % len(widths_range),)
        data.filters = int(filters_option[0]) * 128
        index //= len(filters_range)

        height_option = (index % len(heights_range),) + ((i // len(heights_range)) % len(widths_range),) + ((i // (len(heights_range)*len(widths_range))) % len(kernel_height_range),)
        data.height = int(height_option[0]) * 128
        index //= len(heights_range)

        width_option = (index % len(widths_range),) + ((i // len(widths_range)) % len(kernel_width_range),) + ((i // (len(widths_range)*len(kernel_width_range))) % len(dilation_height_range),)
        data.width = int(width_option[0]) * 128
        index //= len(widths_range)

        kernel_shape_option = (index % len(kernel_height_range),) + ((i // len(kernel_height_range)) % len(kernel_width_range),) + ((i // (len(kernel_height_range)*len(kernel_width_range))) % len(stride_height_range),)
        data.kernel = np.array([[int(x[0]) for x in kernel_shape_option]]).T
        index //= len(kernel_height_range)

        padding_shape_option = (index % len(padding_height_range),) + ((i // len(padding_height_range)) % len(padding_width_range),) + ((i // (len(padding_height_range)*len(padding_width_range))) % len(dilation_height_range),)
        data.padding = np.array([[int(x[0]) for x in padding_shape_option]]).T
        index //= len(padding_height_range)

        stride_shape_option = (index % len(stride_height_range),) + ((i // len(stride_height_range)) % len(stride_width_range),) + ((i // (len(stride_height_range)*len(stride_width_range))) % len(dilation_height_range),)
        data.stride = np.array([[int(x[0]) for x in stride_shape_option]]).T
        index //= len(stride_height_range)

        dilation_shape_option = (index % len(dilation_height_range),) + ((i // len(dilation_height_range)) % len(dilation_width_range),) + ((i // (len(dilation_height_range)*len(dilation_width_range))) % len(kernel_height_range),)
        data.dilation = np.array([[int(x[0]) for x in dilation_shape_option]]).T
        index //= len(dilation_height_range)

        assert_output_shapes(data)


def assert_output_shapes(data):
    input_shape = (1, int(data.filters / 128), int(data.height / 128), int(data.width / 128))
    
    expected_height = convolution_dimension_calculation(int(data.height / 128), data.kernel.shape[0], data.padding[0][0], data.stride[0][0], data.dilation[0][0])
    expected_width = convolution_dimension_calculation(int(data.width / 128), data.kernel.shape[1], data.padding[1][0], data.stride[1][0], data.dilation[1][0])

    builder = Conv2dBuilder()
    builder.set_filters(int(data.filters / 128))
    builder.set_kernel_shape((data.height, data.width))

    if data.padding is not None:
        builder.opt_padding(data.padding)
    
    if data.stride is not None:
        builder.opt_stride(data.stride)

    if data.dilation is not None:
        builder.opt_dilation(data.dilation)

    output = output_shape_for_block(builder.build(), input_shape)
    assert np.array_equal(output, (1, int(data.filters / 128), expected_height, expected_width))


def convolution_dimension_calculation(height, kernel_size, padding, stride, dilation):
    return ((height + 2*padding - kernel_size) // stride + 1) * dilation


# This function is not provided in the original code
def output_shape_for_block(builder, input_shape):
    pass

class Conv2dBuilder:
    def __init__(self):
        self.filters = None
        self.kernel_shape = None
        self.padding = None
        self.stride = None
        self.dilation = None

    def set_filters(self, filters):
        self.filters = filters

    def set_kernel_shape(self, kernel_shape):
        self.kernel_shape = kernel_shape

    def opt_padding(self, padding):
        if self.padding is not None:
            raise ValueError("Padding already specified")
        self.padding = padding

    def opt_stride(self, stride):
        if self.stride is not None:
            raise ValueError("Stride already specified")
        self.stride = stride

    def opt_dilation(self, dilation):
        if self.dilation is not None:
            raise ValueError("Dilation already specified")
        self.dilation = dilation

    def build(self):
        pass
```

Please note that the `output_shape_for_block` function and the `Conv2dBuilder.build()` method are not provided in the original code. You will need to implement these functions according to your specific requirements.