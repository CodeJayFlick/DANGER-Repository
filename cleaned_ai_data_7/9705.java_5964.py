class PopupWindowPlacerBuilder:
    def __init__(self):
        self.head = None
        self.current = None

    def build(self):
        return self.head

    def add(self, next_placer):
        if self.current is None:
            self.current = next_placer
            self.head = self.current
        else:
            self.current.set_next(next_placer)
            self.current = next_placer

    def right_edge(self, *minors):
        return self.edge(Location.RIGHT, *minors)

    def left_edge(self, *minors):
        return self.edge(Location.LEFT, *minors)

    def bottom_edge(self, *minors):
        return self.edge(Location.BOTTOM, *minors)

    def top_edge(self, *minors):
        return self.edge(Location.TOP, *minors)

    def edge(self, major, *minors):
        if len(minors) > 3:
            raise ValueError("Too many preferred Locations: " + str(minors))
        for minor in minors:
            if not major.valid_minor(minor):
                raise ValueError(
                    "Preferred Location " + str(minor) +
                    " is not valid for " + str(major) + " edge."
                )
        if len(minors) == 0:
            # We are defaulting this as greater to lesser
            if major.is_horizontal():
                self.add(EdgePopupPlacer(major, Location.BOTTOM, Location.TOP))
            else:
                self.add(EdgePopupPlacer(major, Location.RIGHT, Location.LEFT))
        elif len(minors) == 1:
            if minors[0] == Location.CENTER:
                # Trying center to greater and then center to lesser.
                if major.is_horizontal():
                    self.add(EdgePopupPlacer(major, minors[0], Location.BOTTOM))
                    self.add(EdgePopupPlacer(major, minors[0], Location.TOP))
                else:
                    self.add(EdgePopupPlacer(major, minors[0], Location.RIGHT))
                    self.add(EdgePopupPlacer(major, minors[0], Location.LEFT))
            else:
                # Only looking from greater/lesser to the center.
                self.add(EdgePopupPlacer(major, minors[0], Location.CENTER))
        else:  # Since we tested len(minors) > 3 above, then we know we must have 2 or 3
            for i in range(len(minors) - 1):
                self.add(EdgePopupPlacer(major, minors[i], minors[i + 1]))

    def then_rotate_clockwise(self):
        if self.current is None:
            return self.rotate_clockwise(Location.BOTTOM, Location.RIGHT)
        else:
            return self.rotate_clockwise(self.current.major, self.current.minor_begin)

    def rotate_clockwise(self, major_begin, minor_begin):
        major = major_begin
        minor = minor_begin
        while True:
            self.add(EdgePopupPlacer(major, minor, major.clockwise()))
            minor = major
            major = major.clockwise()
            if major == major_begin and minor == minor_begin:
                break
        if minor != minor_begin:  # Does remaining portion of initial edge, but repeats first location.
            self.add(EdgePopupPlacer(major, minor, minor_begin))

    def then_rotate_counter_clockwise(self):
        if self.current is None:
            return self.rotate_counter_clockwise(Location.RIGHT, Location.BOTTOM)
        else:
            return self.rotate_counter_clockwise(self.current.major, self.current.minor_begin)

    def rotate_counter_clockwise(self, major_begin, minor_begin):
        major = major_begin
        minor = minor_begin
        while True:
            self.add(EdgePopupPlacer(major, minor, major.counter_clockwise()))
            minor = major
            major = major.counter_clockwise()
            if major == major_begin and minor == minor_begin:
                break
        if minor != minor_begin:  # Does remaining portion of initial edge, but repeats first location.
            self.add(EdgePopupPlacer(major, minor, minor_begin))

    def least_overlap_corner(self):
        self.add(LeastOverlapCornerPopupWindowPlacer())
        return self

    def throws_assert_exception(self):
        self.add(ThrowsAssertExceptionPlacer())
        return self
