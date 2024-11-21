import numpy as np

class TestData:
    def __init__(self):
        self.filters = 0
        self.height = 0
        self.width = 0
        self.kernel = None
        self.padding = None
        self.output_padding = None
        self.stride = None
        self.dilation = None

def assert_output_shapes(data):
    input_shape = (1, data.filters, data.height, data.width)
    
    expected_height = deconvolution_dimension_calculation(data.height, 
                                                           data.kernel[0], 
                                                           data.padding[0], 
                                                           data.output_padding[0], 
                                                           data.stride[0], 
                                                           data.dilation[0])
    expected_width = deconvolution_dimension_calculation(data.width, 
                                                          data.kernel[1], 
                                                          data.padding[1], 
                                                          data.output_padding[1], 
                                                          data.stride[1], 
                                                          data.dilation[1])

    builder = Conv2dTransposeBuilder()
    builder.set_filters(data.filters)
    builder.set_kernel_shape((data.height, data.width))
    if data.padding is not None:
        builder.opt_padding(data.padding)
    if data.output_padding is not None:
        builder.opt_out_padding(data.output_padding)
    if data.stride is not None:
        builder.opt_stride(data.stride)
    if data.dilation is not None:
        builder.opt_dilation(data.dilation)

    output = deconvolution_output_shape(builder.build(), input_shape)
    assert np.array_equal(output, (1, data.filters, expected_height, expected_width))

def deconvolution_dimension_calculation(height, kernel_size, padding, output_padding, stride, dilation):
    return ((height + 2*padding - dilution*(kernel_size-1) + output_padding)/stride)+1

class Conv2dTransposeBuilder:
    def set_filters(self, filters):
        self.filters = filters
    def set_kernel_shape(self, kernel_shape):
        self.kernel_shape = kernel_shape
    def opt_padding(self, padding):
        self.padding = padding
    def opt_out_padding(self, output_padding):
        self.output_padding = output_padding
    def opt_stride(self, stride):
        self.stride = stride
    def opt_dilation(self, dilation):
        self.dilation = dilation

def deconvolution_output_shape(builder, input_shape):
    return (1, builder.filters, ?, ?)
