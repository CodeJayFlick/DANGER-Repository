Here is the translation of the Java code to Python:
```
import numpy as np

class ToTensor:
    def transform(self, array):
        return NDImageUtils.to_tensor(array)

# Note: This assumes that you have a separate function or class called NDImageUtils
# with a method to_tensor() that takes an NDArray-like object and returns a tensor.
```
Note that I did not include the copyright notice and license information in this translation, as it is specific to Java code. Additionally, Python does not require explicit type declarations like Java does, so you will need to define what `NDImageUtils` and its methods are before using them.

Also, please note that `NDArray` and `toTensor()` method might be different from the actual implementation in your case, as it's a part of an AI/ML library.