Here is the translation of the given Java code into Python:

```Python
class NiN:
    def __init__(self):
        pass

    @staticmethod
    def niN(builder):
        nin = NiN()
        block = SequentialBlock()
        for i in range(4):
            block.add(nin.niNBlock(
                builder.numChannels[i],
                Shape((11, 11), (4, 4)),
                Shape((5, 5), (1, 1)),
                Shape((3, 3), (2, 2))
            ))
        block.add(Pool.maxPool2d(Shape((3, 3)), Shape((2, 2))))
        block.add(Dropout(optRate=builder.dropOutRate).build())
        block.add(nin.niNBlock(
            builder.numChannels[3],
            Shape((3, 3)),
            Shape((1, 1)),
            Shape((1, 1))
        ))
        block.add(Pool.globalAvgPool2d().build())
        block.add(Flatten().build())
        return block

    @staticmethod
    def niNBlock(numChannels, kernelShape, strideShape, paddingShape):
        block = SequentialBlock()
        block.add(Conv2D(
            filters=numChannels,
            kernel_shape=kernelShape,
            strides=strideShape,
            padding=paddingShape
        ).build())
        block.add(Activation('relu'))
        for _ in range(2):
            block.add(Conv2D(filters=numChannels, kernel_shape=(1, 1)).build())
            block.add(Activation('relu'))
        return block

    @staticmethod
    def builder():
        class Builder:
            numLayers = 4
            numChannels = [96, 256, 384, 10]
            dropOutRate = 0.5

            def __init__(self):
                pass

            def setDropOutRate(self, rate):
                self.dropOutRate = rate
                return self

            def setNumChannels(self, channels):
                if len(channels) != self.numLayers:
                    raise ValueError("number of channels can be equal to " + str(self.numLayers))
                self.numChannels = channels
                return self

            def build(self):
                return NiN.niN(self)

        return Builder()
```

This Python code is equivalent to the given Java code. It defines a class `NiN` with methods for building and configuring a neural network model, as well as a builder class that can be used to construct instances of this class.