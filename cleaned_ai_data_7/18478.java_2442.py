class LinearGradientView:
    def __init__(self):
        self.mX1 = None
        self.mY1 = None
        self.mX2 = None
        self.mY2 = None
        self.mGradient = []
        self.mGradientUnits = 'OBJECT_BOUNDING_BOX'

    @property
    def x1(self):
        return self.mX1

    @x1.setter
    def set_x1(self, value):
        if isinstance(value, list) and len(value) == 2:
            self.mX1 = [float(x) for x in value]
        else:
            raise ValueError("Invalid input for 'x1'")

    @property
    def y1(self):
        return self.mY1

    @y1.setter
    def set_y1(self, value):
        if isinstance(value, list) and len(value) == 2:
            self.mY1 = [float(x) for x in value]
        else:
            raise ValueError("Invalid input for 'y1'")

    @property
    def x2(self):
        return self.mX2

    @x2.setter
    def set_x2(self, value):
        if isinstance(value, list) and len(value) == 2:
            self.mX2 = [float(x) for x in value]
        else:
            raise ValueError("Invalid input for 'x2'")

    @property
    def y2(self):
        return self.mY2

    @y2.setter
    def set_y2(self, value):
        if isinstance(value, list) and len(value) == 2:
            self.mY2 = [float(x) for x in value]
        else:
            raise ValueError("Invalid input for 'y2'")

    @property
    def gradient(self):
        return self.mGradient

    @gradient.setter
    def set_gradient(self, value):
        if isinstance(value, list):
            self.mGradient = value
        else:
            raise ValueError("Invalid input for 'gradient'")

    @property
    def gradientUnits(self):
        return self.mGradientUnits

    @gradientUnits.setter
    def set_gradient_units(self, value):
        if value in ['OBJECT_BOUNDING_BOX', 'USER_SPACE_ON_USE']:
            self.mGradientUnits = value
        else:
            raise ValueError("Invalid input for 'gradientUnits'")

    def save_definition(self):
        points = [self.mX1[0], self.mY1[0], self.mX2[0], self.mY2[0]]
        brush = {'type': 'LINEAR_GRADIENT', 'points': points, 'units': self.mGradientUnits}
        if len(self.mGradient) > 0:
            brush['colors'] = self.mGradient
        else:
            raise ValueError("Invalid input for 'gradient'")

        svg_view = None

        if self.mGradientUnits == 'USER_SPACE_ON_USE':
            # todo: implement get_canvas_bounds() method in SvgView class
            pass

        # todo: implement define_brush() method in SvgView class
        pass


# Usage:
view = LinearGradientView()
view.set_x1([0, 10])
view.set_y1([0, 20])
view.set_x2([100, 110])
view.set_y2([200, 210])
view.set_gradient([[255, 0], [0, 255]])
view.set_gradient_units('USER_SPACE_ON_USE')
