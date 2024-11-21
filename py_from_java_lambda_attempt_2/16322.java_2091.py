Here is the translation of the Java code into Python:

```Python
class GoogLeNet:
    def __init__(self):
        pass

    @staticmethod
    def goog_le_net(builder: 'GoogLeNet.Builder') -> Block:
        block1 = SequentialBlock()
        block1.add(Conv2d(kernel_shape=(7, 7), filters=64).build())
        block1.add(Activation('relu'))
        block1.add(Pool(max_pool_size=(3, 3), stride=(2, 2)))

        block2 = SequentialBlock()
        block2.add(Conv2d(filters=64, kernel_shape=(1, 1)).build())
        block2.add(Activation('relu'))
        block2.add(Conv2d(filters=192, kernel_shape=(3, 3)).build())
        block2.add(Activation('relu'))
        block2.add(Pool(max_pool_size=(3, 3), stride=(2, 2)))

        block3 = SequentialBlock()
        block3.add(GoogLeNet.inception_block(64, [96, 128], [16, 32], 32))
        block3.add(GoogLeNet.inception_block(128, [128, 192], [32, 96], 64))
        block3.add(Pool(max_pool_size=(3, 3), stride=(2, 2)))

        block4 = SequentialBlock()
        block4.add(GoogLeNet.inception_block(192, [96, 208], [16, 48], 64))
        block4.add(GoogLeNet.inception_block(160, [112, 224], [24, 64], 64))
        block4.add(GoogLeNet.inception_block(128, [128, 256], [24, 64], 64))
        block4.add(GoogLeNet.inception_block(112, [144, 288], [32, 64], 64))
        block4.add(GoogLeNet.inception_block(256, [160, 320], [32, 128], 128))
        block4.add(Pool(max_pool_size=(3, 3), stride=(2, 2)))

        block5 = SequentialBlock()
        block5.add(GoogLeNet.inception_block(256, [160, 320], [32, 128], 128))
        block5.add(GoogLeNet.inception_block(384, [192, 384], [48, 128], 128))
        block5.add(Pool(global_avg_pool_size=(1, 1)))

        return SequentialBlock().addAll(block1, block2, block3, block4, block5, Linear(units=10).build())

    @staticmethod
    def inception_block(c1: int, c2: list[int], c3: list[int], c4: int) -> ParallelBlock:
        p1 = SequentialBlock()
        p1.add(Conv2d(filters=c1, kernel_shape=(1, 1)).build())
        p1.add(Activation('relu'))

        p2 = SequentialBlock()
        p2.add(Conv2d(filters=c2[0], kernel_shape=(1, 1)).build())
        p2.add(Activation('relu'))
        p2.add(Conv2d(filters=c2[1], kernel_shape=(3, 3)).build())
        p2.add(Activation('relu'))

        p3 = SequentialBlock()
        p3.add(Conv2d(filters=c3[0], kernel_shape=(1, 1)).build())
        p3.add(Activation('relu'))
        p3.add(Conv2d(filters=c3[1], kernel_shape=(5, 5)).build())
        p3.add(Activation('relu'))

        p4 = SequentialBlock()
        p4.add(Pool(max_pool_size=(3, 3), stride=(1, 1)))
        p4.add(Conv2d(filters=c4, kernel_shape=(1, 1)).build())
        p4.add(Activation('relu'))

        return ParallelBlock(list=[p1, p2, p3, p4])

    @staticmethod
    def builder() -> 'GoogLeNet.Builder':
        return GoogLeNet.Builder()

class Builder:
    def __init__(self):
        pass

    def build(self) -> Block:
        return GoogLeNet.goog_le_net(self)
```

Note that I've used the `@staticmethod` decorator to define static methods, and the `'GoogLeNet.Builder'` syntax is a type hint indicating that the `builder()` method returns an instance of the `Builder` class.