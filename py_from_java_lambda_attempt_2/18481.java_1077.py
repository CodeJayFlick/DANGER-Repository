Here is a translation of the Java code into equivalent Python:

```Python
class MaskView:
    def __init__(self):
        self.mX = None
        self.mY = None
        self.mW = None
        self.mH = None
        self.sRawMatrix = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
        self.mMatrix = None

    def setX(self, x):
        if isinstance(x, (int, float)):
            self.mX = SVGLength.from_value(x)
        else:
            raise ValueError("Invalid value for 'x'")
        self.invalidate()

    def setY(self, y):
        if isinstance(y, (int, float)):
            self.mY = SVGLength.from_value(y)
        else:
            raise ValueError("Invalid value for 'y'")
        self.invalidate()

    def setWidth(self, width):
        if isinstance(width, (int, float)):
            self.mW = SVGLength.from_value(width)
        else:
            raise ValueError("Invalid value for 'width'")
        self.invalidate()

    def setHeight(self, height):
        if isinstance(height, (int, float)):
            self.mH = SVGLength.from_value(height)
        else:
            raise ValueError("Invalid value for 'height'")
        self.invalidate()

    def setMaskUnits(self, mask_units):
        if mask_units in [0, 1]:
            if mask_units == 0:
                self.mMaskUnits = "OBJECT_BOUNDING_BOX"
            elif mask_units == 1:
                self.mMaskUnits = "USER_SPACE_ON_USE"
        else:
            raise ValueError("Invalid value for 'maskUnits'")
        self.invalidate()

    def setMaskContentUnits(self, mask_content_units):
        if mask_content_units in [0, 1]:
            if mask_content_units == 0:
                self.mMaskContentUnits = "OBJECT_BOUNDING_BOX"
            elif mask_content_units == 1:
                self.mMaskContentUnits = "USER_SPACE_ON_USE"
        else:
            raise ValueError("Invalid value for 'maskContentUnits'")
        self.invalidate()

    def setMaskTransform(self, matrix_array):
        if isinstance(matrix_array, list) and len(matrix_array) > 0:
            sRawMatrix = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
            for i in range(6):
                sRawMatrix[2][i] = matrix_array[i]
        else:
            self.mMatrix = None
        self.invalidate()

    def saveDefinition(self):
        if hasattr(self, 'mName'):
            svg = getSvgView()
            svg.defineMask(self, self.mName)
```

Note that this is a direct translation of the Java code into Python. The original Java code seems to be part of an Android app using React Native and SVG graphics, so some parts may not work as-is in pure Python (e.g., `ReactContext`, `ReadableArray`).