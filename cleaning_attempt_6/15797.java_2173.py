import math

class ShapeUtils:
    def __init__(self):
        pass

    @staticmethod
    def output_shape_for_block(manager, block, input_shape):
        outputs = block.get_output_shapes([input_shape])
        return outputs[0]

    @staticmethod
    def convolution_dimension_calculation(dimension, kernel_component, pad_component, stride_component, dilation_component):
        return math.floor((dimension + 2 * pad_component - dilation_component * (kernel_component - 1) - 1) / stride_component) + 1

    @staticmethod
    def deconvolution_dimension_calculation(dimension, kernel_component, pad_component, output_pad_component, stride_component, dilation_component):
        return ((dimension - 1) * stride_component - 2 * pad_component + dilation_component * (kernel_component - 1) + output_pad_component) + 1

# Example usage:
manager = None
block = None
input_shape = [10, 20, 30]
output_shape = ShapeUtils.output_shape_for_block(manager, block, input_shape)
print(output_shape)

dimension = 100
kernel_component = 3
pad_component = 2
stride_component = 4
dilation_component = 1
convolution_output_dimension = ShapeUtils.convolution_dimension_calculation(dimension, kernel_component, pad_component, stride_component, dilation_component)
print(convolution_output_dimension)

deconvolution_input_dimension = 100
kernel_component_deconvolution = 3
pad_component_deconvolution = 2
output_pad_component_deconvolution = 1
stride_component_deconvolution = 4
dilation_component_deconvolution = 1
deconvolution_output_dimension = ShapeUtils.deconvolution_dimension_calculation(deconvolution_input_dimension, kernel_component_deconvolution, pad_component_deconvolution, output_pad_component_deconvolution, stride_component_deconvolution, dilation_component_deconvolution)
print(deconvolution_output_dimension)
