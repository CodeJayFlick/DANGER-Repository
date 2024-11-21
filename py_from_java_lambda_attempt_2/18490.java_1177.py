Here is your Java code translated into Python:

```Python
class RNSVGMarkerType:
    kStartMarker = 'kStartMarker'
    kMidMarker = 'kMidMarker'
    kEndMarker = 'kEndMarker'

class ElementType:
    kCGPathElementAddCurveToPoint = 0
    kCGPathElementAddQuadCurveToPoint = 1
    kCGPathElementMoveToPoint = 2
    kCGPathElementAddLineToPoint = 3
    kCGPathElementCloseSubpath = 4

class Point:
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y

class SegmentData:
    def __init__(self):
        self.start_tangent = None
        self.end_tangent = None
        self.position = None

class RNSVGMarkerPosition:
    positions_ = []
    element_index_ = 0
    origin_ = Point(0, 0)
    subpath_start_ = Point(0, 0)
    in_slope_ = None
    out_slope_ = None
    auto_start_reverse_ = False

    def __init__(self, type: RNSVGMarkerType, origin: Point, angle: float):
        self.type = type
        self.origin = origin
        self.angle = angle

    @staticmethod
    def from_path(elements):
        positions_.clear()
        element_index_ = 0
        for e in elements:
            UpdateFromPathElement(e)
        PathIsDone()
        return positions_

    @staticmethod
    def path_is_done():
        angle = CurrentAngle(RNSVGMarkerType.kEndMarker)
        positions_.append(RNSVGMarkerPosition(RNSVGMarkerType.kEndMarker, origin_, angle))

    @staticmethod
    def bisecting_angle(in_angle: float, out_angle: float):
        if abs(in_angle - out_angle) > 180:
            in_angle += 360
        return (in_angle + out_angle) / 2

    @staticmethod
    def rad_to_deg(rad: float):
        RNSVG_radToDeg = 180 / math.pi
        return rad * RNSVG_radToDeg

    @staticmethod
    def slope_angle_radians(p: Point):
        return math.atan2(p.y, p.x)

    @staticmethod
    def current_angle(type: RNSVGMarkerType):
        in_angle = rad_to_deg(slope_angle_radians(in_slope_))
        out_angle = rad_to_deg(slope_angle_radians(out_slope_))

        if type == RNSVGMarkerType.kStartMarker:
            if auto_start_reverse_:
                out_angle += 180
            return out_angle

        elif type == RNSVGMarkerType.kMidMarker:
            return bisecting_angle(in_angle, out_angle)

        elif type == RNSVGMarkerType.kEndMarker:
            return in_angle

    @staticmethod
    def subtract(p1: Point, p2: Point):
        return Point(p2.x - p1.x, p2.y - p1.y)

    @staticmethod
    def is_zero(p: Point):
        return p.x == 0 and p.y == 0

    @staticmethod
    def compute_quad_tangents(data: SegmentData, start: Point, control: Point, end: Point):
        data.start_tangent = subtract(control, start)
        data.end_tangent = subtract(end, control)

        if is_zero(data.start_tangent):
            data.start_tangent = data.end_tangent
        elif is_zero(data.end_tangent):
            data.end_tangent = data.start_tangent

    @staticmethod
    def extract_path_element_features(element: ElementType):
        data = SegmentData()
        points = element.points
        if isinstance(element, int):
            switcher = {
                0: lambda: (data.position, subtract(points[0], RNSVGMarkerPosition.origin_),
                            subtract(points[2], points[1])),
                1: lambda: (points[1], subtract(RNSVGMarkerPosition.origin_, points[0]),
                            subtract(points[1], points[0]))
            }
            switcher.get(element.type, lambda: None)()
        return data

    @staticmethod
    def update_from_path_element(element):
        segment_data = extract_path_element_features(element)
        RNSVGMarkerPosition.out_slope_ = segment_data.start_tangent
        if element_index_ > 0:
            marker_type = RNSVGMarkerType.kStartMarker if element_index_ == 1 else RNSVGMarkerType.kMidMarker
            angle = CurrentAngle(marker_type)
            positions_.append(RNSVGMarkerPosition(marker_type, origin_, angle))
        RNSVGMarkerPosition.in_slope_ = segment_data.end_tangent
        RNSVGMarkerPosition.origin_ = segment_data.position

        if element.type == ElementType.kCGPathElementMoveToPoint:
            subpath_start_ = points[0]
        elif element.type == ElementType.kCGPathElementCloseSubpath:
            subpath_start_ = Point(0, 0)
        else:
            subpath_start_ = origin_

        RNSVGMarkerPosition.element_index_ += 1

    @staticmethod
    def path_is_done():
        angle = CurrentAngle(RNSVGMarkerType.kEndMarker)
        positions_.append(RNSVGMarkerPosition(RNSVGMarkerType.kEndMarker, origin_, angle))
```

Please note that I have not tested this code. It is possible that there are errors or missing parts in the translation process.