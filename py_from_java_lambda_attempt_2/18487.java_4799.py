Here's your Java code translated into Python:

```Python
class RectView:
    def __init__(self):
        pass

    def set_x(self, x):
        self.mX = SVGLength.from(x)
        self.invalidate()

    def set_y(self, y):
        self.mY = SVGLength.from(y)
        self.invalidate()

    def set_width(self, width):
        self.mW = SVGLength.from(width)
        self.invalidate()

    def set_height(self, height):
        self.mH = SVGLength.from(height)
        self.invalidate()

    def set_rx(self, rx):
        self.mRx = SVGLength.from(rx)
        self.invalidate()

    def set_ry(self, ry):
        self.mRy = SVGLength.from(ry)
        self.invalidate()

    def get_path(self, canvas, paint):
        path = Path()
        x = self.relative_on_width(self.mX)
        y = self.relative_on_height(self.mY)
        w = self.relative_on_width(self.mW)
        h = self.relative_on_height(self.mH)

        if self.mRx is not None or self.mRy is not None:
            rx = 0
            ry = 0

            if self.mRx is None:
                ry = self.relative_on_height(self.mRy)
                rx = ry
            elif self.mRy is None:
                rx = self.relative_on_width(self.mRx)
                ry = rx
            else:
                rx = self.relative_on_width(self.mRx)
                ry = self.relative_on_height(self.mRy)

            if rx > w / 2:
                rx = w / 2

            if ry > h / 2:
                ry = h / 2

            path.add_rounded_rect(x, y, x + w, y + h, rx, ry, Path.Direction.CW)
        else:
            path.add_rect(x, y, x + w, y + h, Path.Direction.CW)

        return path


class SVGLength:
    @staticmethod
    def from(value):
        pass

    @staticmethod
    def relative_on_width(length):
        pass

    @staticmethod
    def relative_on_height(height):
        pass
```

Please note that Python does not have direct equivalents for Java's `@Override`, `@ReactProp` and other annotations. Also, the code you provided seems to be part of a larger program, so I've left out some parts (like ReactContext) as they are specific to your application.

Also, this is just one possible translation - there may be many ways to translate Java into Python depending on how exactly you want things done in Python.