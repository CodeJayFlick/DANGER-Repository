import math

class VisualEdgeArrowRenderingSupport:
    def create_arrow_transform(self, rc, edge_shape, vertex_shape):
        return self.do_create_arrow_transform(rc.get_arrow_placement_tolerance(), edge_shape, vertex_shape)

    def do_create_arrow_transform(self, arrow_placement_tolerance, edge_shape, vertex_shape):
        path = GeneralPath(edge_shape)
        seg = [0] * 6
        p1 = None
        p2 = None
        at = AffineTransform()

        for i in iter(path.get_path_iterator()):
            type = i.current_segment(seg)
            if type == PathIterator.SEG_MOVETO:
                p2 = Point2D.Double(*seg[:2])
            elif type == PathIterator.SEG_LINETO:
                p1 = p2
                p2 = Point2D.Double(*seg[:2])
                if vertex_shape.contains(p2):
                    line_segment = Line2D.Double(*p1, *p2)
                    return self.create_arrow_transform_from_line(self.find_closest_line_segment(arrow_placement_tolerance, line_segment, vertex_shape))

        return at

    def find_closest_line_segment(self, arrow_placement_tolerance, line, vertex_shape):
        if not vertex_shape.contains(line.get_p2()):
            raise ValueError(f"line end point: {line.get_p2()} is not contained in shape: {vertex_shape.getBounds()}")
        
        left = Line2D.Double()
        right = Line2D.Double()

        iterations = 0
        while length_squared(line) > arrow_placement_tolerance and iterations < 15:
            self.bisect(line, left, right)
            line = vertex_shape.contains(right.get_p1()) and left or right
            iterations += 1

        return line

    def length_squared(self, line):
        dx = line.x1 - line.x2
        dy = line.y1 - line.y2
        return dx * dx + dy * dy

    def bisect(self, src, left, right):
        x1, y1 = src.x1, src.y1
        x2, y2 = src.x2, src.y2
        mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
        left.set_line(x1, y1, mx, my)
        right.set_line(mx, my, x2, y2)

    def create_arrow_transform_from_line(self, line):
        x1, y1 = line.x1, line.y1
        dx, dy = x1 - line.x2, y1 - line.y2
        atheta = math.atan2(dx, dy) + math.pi / 2.0
        at = AffineTransform()
        at.translate(x1, y1)
        at.rotate(-atheta)

        return at

class GeneralPath:
    def __init__(self, edge_shape):
        pass

    def get_path_iterator(self):
        pass

class PathIterator:
    SEG_MOVETO = 0
    SEG_LINETO = 1

class Point2D:
    Double = None

class Line2D:
    Double = None

    def set_line(self, x1, y1, x2, y2):
        self.x1, self.y1, self.x2, self.y2 = x1, y1, x2, y2

    def get_p1(self):
        return self.x1, self.y1

    def get_p2(self):
        return self.x2, self.y2
