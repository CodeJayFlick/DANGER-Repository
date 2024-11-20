from shapely.geometry import Polygon, Point

class BoundingBox:
    def __init__(self):
        pass

    def get_bounds(self) -> tuple:
        # TO DO: implement this method to return the bounding box coordinates as a tuple of (x1, y1, x2, y2)
        raise NotImplementedError("Method not implemented")

    def get_path(self) -> list:
        # TO DO: implement this method to return an iterable object that iterates along the BoundingBox boundary
        raise NotImplementedError("Method not implemented")

    def get_point(self) -> Point:
        # TO DO: implement this method to return the top left point of the bounding box as a shapely.geometry.Point object
        raise NotImplementedError("Method not implemented")

    def get_iou(self, other_bbox: 'BoundingBox') -> float:
        # TO DO: implement this method to calculate and return the Intersection over Union (IoU) value between two BoundingBox objects
        raise NotImplementedError("Method not implemented")
