Here is the translation of the Java code into Python:

```Python
class ResNetV1:
    def __init__(self):
        pass

    @staticmethod
    def residual_unit(num_filters, stride, dim_match, bottleneck, batch_norm_momentum):
        res_unit = Sequential()
        if bottleneck:
            res_unit.add(Conv2D(1, 1, num_filters // 4))
            res_unit.add(BatchNormalization(momentum=batch_norm_momentum))
            res_unit.add(Activation('relu'))
            res_unit.add(Conv2D(3, 3, num_filters // 4))
            res_unit.add(BatchNormalization(momentum=batch_norm_momentum))
            res_unit.add(Activation('relu'))
            res_unit.add(Conv2D(1, 1, num_filters))
        else:
            res_unit.add(Conv2D(3, 3, num_filters))
            res_unit.add(BatchNormalization(momentum=batch_norm_momentum))
            res_unit.add(Activation('relu'))

        shortcut = Sequential()
        if dim_match:
            shortcut.add(identity_block())
        else:
            shortcut.add(Conv2D(1, 1, num_filters))

        return Parallel()(res_unit, shortcut)

    @staticmethod
    def resnet(builder):
        num_stages = len(builder.units)
        height = builder.image_shape[1]
        if height <= 32:
            res_net = Sequential()
            res_net.add(Conv2D(3, 7, builder.filters[0]))
            res_net.add(BatchNormalization(momentum=builder.batch_norm_momentum))
            res_net.add(Activation('relu'))
            res_net.add(MaxPooling2D((3, 3), strides=(2, 2)))
        else:
            res_net = Sequential()
            res_net.add(Conv2D(3, 7, builder.filters[0]))
            res_net.add(BatchNormalization(momentum=builder.batch_norm_momentum))
            res_net.add(Activation('relu'))
            res_net.add(MaxPooling2D((3, 3), strides=(2, 2)))

        stride = (1, 1)
        for i in range(num_stages):
            if height <= 28:
                per_unit = len(builder.units) - 2
                filters = [16, 64, 128, 256]
                bottleneck = True
            else:
                filters = [64, 256, 512, 1024, 2048]
                bottleneck = True

            units = builder.units[i] * per_unit
            for j in range(units):
                res_net.add(ResNetV1.residual_unit(filters[0], stride, False, bottleneck, batch_norm_momentum=builder.batch_norm_momentum))
                if i < num_stages - 1:
                    stride = (2, 2)
                else:
                    stride = (1, 1)

        return res_net.add(GlobalAveragePooling2D()), res_net.add(Flatten()), Dense(builder.out_size), Flatten()

    @staticmethod
    def builder():
        class Builder:
            num_layers = None
            out_size = None
            batch_norm_momentum = 0.9
            image_shape = None
            bottleneck = True
            units = []
            filters = []

            def set_num_layers(self, num_layers):
                self.num_layers = num_layers
                return self

            def set_out_size(self, out_size):
                self.out_size = out_size
                return self

            def opt_batch_norm_momentum(self, batch_norm_momentum):
                self.batch_norm_momentum = batch_norm_momentum
                return self

            def set_image_shape(self, image_shape):
                self.image_shape = image_shape
                return self

            def build(self):
                if not self.image_shape:
                    raise ValueError("Must set imageShape")

                height = self.image_shape[1]
                if height <= 28:
                    num_stages = 3
                    per_unit = (self.num_layers - 2) // 9
                    filters = [16, 64, 128, 256]
                    bottleneck = True

                    units = []
                    for i in range(num_stages):
                        units.append(per_unit)

                else:
                    num_stages = 4
                    if self.num_layers >= 50:
                        filters = [64, 256, 512, 1024, 2048]
                        bottleneck = True

                    elif self.num_layers == 18:
                        units = [2, 2, 2, 2]

                    elif self.num_layers in (34, 50):
                        units = [3, 4, 6, 3]

                    elif self.num_layers >= 101:
                        if self.num_layers == 152 or self.num_layers == 200 or self.num_layers == 269:
                            units = [3, 8, 36, 3]
                        else:
                            raise ValueError("no experiments done on num_ layers " + str(self.num_layers) + ", you can do it yourself")

                    return ResNetV1.resnet(self)

        return Builder()
```

Please note that this is a direct translation of the Java code into Python. The original Java code seems to be part of some larger project, and there may not be an exact equivalent in Python due to differences between languages (e.g., Java's `Block` class does not have a direct equivalent in Python).