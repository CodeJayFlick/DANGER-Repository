Here is the translation of the Java code into Python:

```Python
import numpy as np

class Activation:
    def __init__(self):
        pass

    @staticmethod
    def relu(array):
        return array.getNDArrayInternal().relu()

    @staticmethod
    def sigmoid(array):
        return array.getNDArrayInternal().sigmoid()

    @staticmethod
    def tanh(array):
        return array.getNDArrayInternal().tanh()

    @staticmethod
    def softPlus(array):
        return array.getNDArrayInternal().softPlus()

    @staticmethod
    def softSign(array):
        return array.getNDArrayInternal().softSign()

    @staticmethod
    def leakyRelu(array, alpha):
        return array.getNDArrayInternal().leakyRelu(alpha)

    @staticmethod
    def elu(array, alpha):
        return array.getNDArrayInternal().elu(alpha)

    @staticmethod
    def selu(array):
        return array.getNDArrayInternal().selu()

    @staticmethod
    def gelu(array):
        return array.getNDArrayInternal().gelu()

    @staticmethod
    def swish(array, beta):
        return array.getNDArrayInternal().swish(beta)

    @staticmethod
    def mish(array):
        return array.getNDArrayInternal().mish()

class LambdaBlock:
    def __init__(self, func):
        self.func = func

    def forward(self, arrays):
        if isinstance(arrays, list) and len(arrays) == 1:
            return [self.func(np.array([arrays[0]]))[0]]
        else:
            return [self.func(array)[0] for array in arrays]

class Prelu(LambdaBlock):
    def __init__(self):
        super().__init__(Activation.leakyRelu)

# Example usage
activation = Activation()
lambda_block = LambdaBlock(activation.relu)
prelu_block = Prelu()

print(lambda_block.forward([[1, 2], [3, 4]]))
print(prelu_block.forward([5]))
```