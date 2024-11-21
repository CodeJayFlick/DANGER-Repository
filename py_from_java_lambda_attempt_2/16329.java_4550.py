Here is the translation of the Java code into Python:

```Python
class VGG:
    def __init__(self):
        pass

    @staticmethod
    def vgg(builder):
        block = SequentialBlock()
        for conv_arch in builder.conv_arch:
            block.add(VGG.vgg_block(conv_arch[0], conv_arch[1]))
        
        block.add(BatchFlatten())
        block.add(Linear(units=4096))
        block.add(ReLU())
        block.add(Dropout(rate=0.5))
        block.add(Linear(units=4096))
        block.add(ReLU())
        block.add(Dropout(rate=0.5))
        block.add(Linear(units=10))

        return block

    @staticmethod
    def vgg_block(num_convs, num_channels):
        temp_block = SequentialBlock()
        for i in range(num_convs):
            temp_block.add(Conv2d(filters=num_channels, kernel_shape=(3, 3), padding='same'))
            temp_block.add(ReLU())
        
        temp_block.add(MaxPool2D((2, 2)))
        return temp_block

    @staticmethod
    def builder():
        class Builder:
            num_layers = 11
            conv_arch = [[1, 64], [1, 128], [2, 256], [2, 512], [2, 512]]

            def set_num_layers(self, num_layers):
                self.num_layers = num_layers
                return self

            def set_conv_arch(self, conv_arch):
                total_sum = sum(len(layer) for layer in conv_arch)
                if total_sum != (self.num_layers - 3):
                    raise ValueError("total sum of channels should be equal to the (numLayers - 3)")
                
                self.conv_arch = conv_arch
                return self

            def build(self):
                return VGG.vgg(self)

        return Builder()

class SequentialBlock:
    pass

class BatchFlatten():
    pass

class Linear:
    @staticmethod
    def builder(units=1):
        class Builder:
            units = units
            
            def set_units(self, units):
                self.units = units
                return self
        
        return Builder()

class ReLU():
    pass

class Dropout:
    @staticmethod
    def builder(rate=0.5):
        class Builder:
            rate = rate
            
            def opt_rate(self, rate):
                self.rate = rate
                return self
        
        return Builder()

class Conv2d:
    @staticmethod
    def builder(filters=1, kernel_shape=(3, 3), padding='same'):
        class Builder:
            filters = filters
            kernel_shape = kernel_shape
            padding = padding
            
            def set_filters(self, filters):
                self.filters = filters
                return self
            
            def set_kernel_shape(self, kernel_shape):
                self.kernel_shape = kernel_shape
                return self
            
            def opt_padding(self, padding):
                self.padding = padding
                return self
        
        return Builder()

class MaxPool2D:
    @staticmethod
    def builder(pool_size=(1, 1)):
        class Builder:
            pool_size = pool_size
            
            def set_pool_size(self, pool_size):
                self.pool_size = pool_size
                return self
        
        return Builder()
```

This Python code defines a VGG model and its components. The `VGG` class contains methods to create the convolutional blocks (`vgg_block`) and the fully connected layers of the network (`vgg`). The `Builder` class is used to construct the `VGG` object with specific parameters, such as the number of layers and the architecture of the convolutional blocks.