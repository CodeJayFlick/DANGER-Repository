Here is the translation of the given Java code into Python:

```Python
class AlexNet:
    def __init__(self):
        pass

def alex_net(builder):
    block = SequentialBlock()
    block.add(Conv2d(kernel_shape=(11, 11), stride=4, filters=builder.num_channels[0]))
    block.add(Activation('relu'))
    block.add(Pool(max_pool_size=(3, 3), stride=2))
    
    # Make the convolution window smaller
    block.add(Conv2d(kernel_shape=(5, 5), padding='same', filters=builder.num_channels[1]))
    block.add(Activation('relu'))
    block.add(Pool(max_pool_size=(3, 3), stride=2))

    # Use three successive convolutional layers and a smaller convolution window
    for _ in range(4):
        block.add(Conv2d(kernel_shape=(3, 3), padding='same', filters=builder.num_channels[2]))
        block.add(Activation('relu'))

    block.add(BatchFlatten())
    block.add(Dense(units=builder.num_channels[5], activation='relu'))
    block.add(Dropout(rate=builder.dropout_rate))
    block.add(Dense(units=builder.num_channels[6], activation='relu'))
    block.add(Dropout(rate=builder.dropout_rate))
    
    # Output layer
    block.add(Dense(units=10))

def builder():
    return AlexNetBuilder()

class Builder:
    def __init__(self):
        self.drop_out_rate = 0.5
        self.num_layers = 7
        self.num_channels = [96, 256, 384, 384, 256, 4096, 4096]

    def set_dropout_rate(self, drop_out_rate):
        self.drop_out_rate = drop_out_rate
        return self

    def set_num_channels(self, num_channels):
        if len(num_channels) != self.num_layers:
            raise ValueError("number of channels should be equal to " + str(self.num_layers))
        
        self.num_channels = num_channels
        return self

    def build(self):
        return alex_net(self)
```

Please note that this is a direct translation from Java code, and it may not work as expected without proper testing.