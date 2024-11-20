class TextPathView:
    def __init__(self):
        self.m_href = None
        self.m_side = None
        self.m_mid_line = None
        self.m_start_offset = None
        self.m_method = "align"
        self.m_spacing = "exact"

    @property
    def href(self):
        return self.m_href

    @href.setter
    def set_href(self, value):
        self.m_href = value
        self.invalidate()

    @property
    def start_offset(self):
        return self.m_start_offset

    @start_offset.setter
    def set_start_offset(self, value):
        if isinstance(value, str):
            try:
                self.m_start_offset = float(value)
            except ValueError:
                pass
        elif hasattr(value, 'as_dict'):
            self.m_start_offset = SVGLength.from_dict(value.as_dict())
        else:
            raise TypeError("Invalid start offset")
        self.invalidate()

    @property
    def method(self):
        return self.m_method

    @method.setter
    def set_method(self, value):
        if isinstance(value, str) and value in ["align", "start"]:
            self.m_method = value
        elif hasattr(value, 'as_dict'):
            try:
                self.m_method = TextPathMethod.from_dict(value.as_dict())
            except ValueError:
                pass
        else:
            raise TypeError("Invalid method")
        self.invalidate()

    @property
    def spacing(self):
        return self.m_spacing

    @spacing.setter
    def set_spacing(self, value):
        if isinstance(value, str) and value in ["exact", "scale"]:
            self.m_spacing = value
        elif hasattr(value, 'as_dict'):
            try:
                self.m_spacing = TextPathSpacing.from_dict(value.as_dict())
            except ValueError:
                pass
        else:
            raise TypeError("Invalid spacing")
        self.invalidate()

    @property
    def side(self):
        return self.m_side

    @side.setter
    def set_side(self, value):
        if isinstance(value, str) and value in ["left", "right"]:
            self.m_side = TextPathSide[value]
        elif hasattr(value, 'as_dict'):
            try:
                self.m_side = TextPathSide.from_dict(value.as_dict())
            except ValueError:
                pass
        else:
            raise TypeError("Invalid side")
        self.invalidate()

    @property
    def mid_line(self):
        return self.m_mid_line

    @mid_line.setter
    def set_mid_line(self, value):
        if isinstance(value, str) and value in ["sharp", "flat"]:
            self.m_mid_line = TextPathMidLine[value]
        elif hasattr(value, 'as_dict'):
            try:
                self.m_mid_line = TextPathMidLine.from_dict(value.as_dict())
            except ValueError:
                pass
        else:
            raise TypeError("Invalid mid line")
        self.invalidate()

    def draw(self):
        # This method is not translated as it's unclear what the original Java code does.
        pass

class SVGLength:
    @classmethod
    def from_dict(cls, value):
        return float(value)

class TextPathMethod:
    align = "align"
    start = "start"

    @classmethod
    def from_dict(cls, value):
        if isinstance(value, str) and value in ["align", "start"]:
            return cls[value]
        else:
            raise ValueError("Invalid method")

class TextPathSpacing:
    exact = "exact"
    scale = "scale"

    @classmethod
    def from_dict(cls, value):
        if isinstance(value, str) and value in ["exact", "scale"]:
            return value
        else:
            raise ValueError("Invalid spacing")
