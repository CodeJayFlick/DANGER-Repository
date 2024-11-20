import unittest
from typing import Tuple

class TestData:
    def __init__(self):
        self.filters = 0
        self.width = 0
        self.kernel = None
        self.padding = None
        self.stride = None
        self.dilation = None

def assert_output_shapes(data: TestData) -> None:
    input_shape = (1, data.filters, data.width)
    expected_width = convolution_dimension_calculation(
        data.width,
        data.kernel[0],
        data.padding[0],
        data.stride[0],
        data.dilation[0]
    )

    builder = Conv1d.Builder()
    .set_filters(data.filters)
    .set_kernel_shape(tuple(data.kernel))
    .opt_padding(tuple(data.padding))
    .opt_stride(tuple(data.stride))
    .opt_dilation(tuple(data.dilation))

    output = output_shape_for_block(builder.build(), input_shape)
    assert expected_width == data.width

def convolution_dimension_calculation(width: int, kernel_size: int, padding: int, stride: int, dilation: int) -> int:
    return (width + 2 * padding - kernel_size) // stride * dilation

class Conv1dTest(unittest.TestCase):
    def test_output_shapes(self) -> None:
        filters = range(1, 4)
        widths = range(1, 5)
        kernel_width_range = range(1, 6)
        padding_width_range = range(0, 6)
        stride_width_range = range(1, 6)
        dilation_width_range = range(1, 6)

        rows = len(list(filters)) * len(list(widths)) * len(list(kernel_width_range)) * len(list(padding_width_range)) * len(list(stride_width_range)) * len(list(dilation_width_range))

        if 'nightly' in os.environ:
            stream_to_test = range(0, rows)
        else:
            stream_to_test = range(1, rows)

        for ix in stream_to_test:
            data = TestData()
            filters_option = (ix % len(filters),) + filters
            data.filters *= 128
            width_option = (ix % len(widths),) + widths
            data.width *= 128

            kernel_option = (ix % len(kernel_width_range),) + kernel_width_range
            data.kernel = tuple(kernel_option)

            padding_option = (ix % len(padding_width_range),) + padding_width_range
            data.padding = tuple(padding_option)

            stride_option = (ix % len(stride_width_range),) + stride_width_range
            data.stride = tuple(stride_option)

            dilation_option = (ix % len(dilation_width_range),) + dilation_width_range
            data.dilation = tuple(dilation_option)

            assert_output_shapes(data)
