from shapely.geometry import LineString, Point
import math

class ArticulatedEdgeTransformer:
    def __init__(self):
        pass

    def apply(self, e: tuple) -> object:
        start = e[0]
        end = e[1]

        is_loop = start == end
        if is_loop:
            return self.create_hollow_edge_loop()

        p1 = Point(start['x'], start['y'])
        if not p1.x or not p1.y:
            log_missing_location(e, start)
            return None

        p2 = Point(end['x'], end['y'])
        if not p2.x or not p2.y:
            log_missing_location(e, end)
            return None

        articulations = e[2]
        origin_x = p1.x
        origin_y = p1.y

        path = LineString()
        for pt in articulations:
            x = (pt['x'] - origin_x) + 0.0
            y = (pt['y'] - origin_y) + 0.0
            path.append(Point(x, y))

        p2x = (p2.x - origin_x)
        p2y = (p2.y - origin_y)
        path.append(Point(p2x, p2y))
        path.close()

        transform = self.get_transform(origin_x, origin_y, p1['x'], p1['y'], p2['x'], p2['y'])
        return transform.transform(path)

    def create_hollow_edge_loop(self):
        # todo: implement this method
        pass

    def get_overlap_offset(self, e):
        # todo: implement this method
        pass

    def log_missing_location(self, e, v):
        if not SystemUtilities.is_in_testing_mode():
            return
        raise Exception("Edge vertex is missing a location")

class SystemUtilities:
    @staticmethod
    def is_in_testing_mode():
        # todo: implement this method
        pass


# usage example:

transformer = ArticulatedEdgeTransformer()
e = (Point(0, 0), Point(1, 1), [(0.5, 0.5)])
shape = transformer.apply(e)
