Here is the translation of the Java code into Python:

```Python
import numpy as np
from PIL import ImageEnhance

class RandomColorJitter:
    def __init__(self, brightness: float, contrast: float, saturation: float, hue: float):
        self.brightness = brightness
        self.contrast = contrast
        self.saturation = saturation
        self.hue = hue

    def transform(self, array: np.ndarray) -> np.ndarray:
        enhancer = ImageEnhance.Color(array)
        color_jittered_array = enhancer.enhance(np.random.uniform(0.5, 1.5))
        
        return color_jittered_array
```

Please note that this Python code is not a direct translation of the Java code as it uses different libraries and methods to achieve similar results.