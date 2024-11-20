Here is the translation of the Java code into Python:

```Python
import colorsys
from typing import Tuple

class ColorUtils:
    HUE_RED = 0.0 / 12
    HUE_ORANGE = 1.0 / 12
    HUE_YELLOW = 2.0 / 12
    HUE_LIME = 3.0 / 12
    HUE_GREEN = 4.0 / 12
    HUE_PINE = 5.0 / 12
    HUE_TURQUISE = 6.0 / 12
    HUE_SAPPHIRE = 7.0 / 12
    HUE_BLUE = 8.0 / 12
    HUE_ROYAL = 9.0 / 12
    HUE_PURPLE = 10.0 / 12
    HUE_PINK = 11.0 / 12

    @staticmethod
    def derive_background(src: Tuple[float, float, float], hue: float, sfact: float, bfact: float) -> Tuple[float, float, float]:
        vals = [0.0] * 3
        colorsys.rgb_to_hls(*map(lambda x: x / 255, src))[:2] + [vals[2]] = (hue, sfact, bfact)
        return tuple(map(lambda x: round(x * 255), colorsys.hls_to_rgb(*vals)))

    @staticmethod
    def derive_background(bg: Tuple[float, float, float], hue: float) -> Tuple[float, float, float]:
        return ColorUtils.derive_background(bg, hue, 1.0, 0.9)

    @staticmethod
    def derive_foreground(bg: Tuple[float, float, float], hue: float, brt: float) -> Tuple[float, float, float]:
        vals = [0.0] * 3
        colorsys.rgb_to_hls(*map(lambda x: x / 255, bg))[:2] + [vals[2]] = (hue, 1 - abs(vals[1]), brt)
        return tuple(map(lambda x: round(x * 255), colorsys.hls_to_rgb(*vals)))

    @staticmethod
    def derive_foreground(bg: Tuple[float, float, float], hue: float) -> Tuple[float, float, float]:
        return ColorUtils.derive_foreground(bg, hue, 1.0)

    @staticmethod
    def contrast_foreground(color: Tuple[float, float, float]) -> Tuple[float, float, float]:
        rgbs = [0.0] * 3
        color[0] > 0.5 and (rgbs[0], rgbs[1], rgbs[2]) = ((color[0] - 1) / 2, (color[1] - 1) / 2, (color[2] - 1) / 2)
        return tuple(map(lambda x: round(x * 255), colorsys.rgb_to_hls(*rgbs)))

    @staticmethod
    def blend(c1: Tuple[float, float, float], c2: Tuple[float, float, float], ratio: float) -> Tuple[float, float, float]:
        rgb1 = [0.0] * 3
        rgb2 = [0.0] * 3
        colorsys.rgb_to_hls(*map(lambda x: x / 255, c1))[:2] + [rgb1[2]] = (c1[0], c1[1], c1[2])
        colorsys.rgb_to_hls(*map(lambda x: x / 255, c2))[:2] + [rgb2[2]] = (c2[0], c2[1], c2[2])

        inverse = 1 - ratio
        return tuple(map(lambda x: round(x * 255), colorsys.hls_to_rgb(ratio * rgb1[0] + inverse * rgb2[0],
                                                                              ratio * rgb1[1] + inverse * rgb2[1],
                                                                              ratio * rgb1[2] + inverse * rgb2[2])))

    class ColorBlender:
        def __init__(self):
            self.r = 0
            self.g = 0
            self.b = 0
            self.a = 0

        def add(self, color: Tuple[float, float, float]) -> None:
            ca = color[3]
            self.a += ca
            self.r += ca * color[0] / 255
            self.g += ca * color[1] / 255
            self.b += ca * color[2] / 255

        def clear(self) -> None:
            self.r = 0
            self.g = 0
            self.b = 0
            self.a = 0

        def get_color(self, default_color: Tuple[float, float, float]) -> Tuple[float, float, float]:
            if self.a == 0:
                return default_color
            return tuple(map(lambda x: round(x * 255), (self.r / self.a, self.g / self.a, self.b / self.a)))
```

Please note that the Python code is not exactly equivalent to the Java code. The main differences are:

1. In Python, we use `tuple` instead of arrays.
2. We don't need explicit casting for primitive types like int and float in Python.
3. Some methods have been modified slightly due to differences between Java's Math library and Python's math library.

Also note that the color conversion functions (`rgb_to_hls`, `hls_to_rgb`) are not exactly equivalent, as they use different libraries (Java's built-in vs Python's colorsys).