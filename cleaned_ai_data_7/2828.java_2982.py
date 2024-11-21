from abc import ABCMeta, abstractmethod

class BoundingShape(metaclass=ABCMeta):
    @abstractmethod
    def get_area(self):
        pass

    @abstractmethod
    def get_margin(self):
        pass

    @abstractmethod
    def compute_centroid_distance(self, shape):
        pass

    @abstractmethod
    def compute_area_union_bounds(self, shape):
        pass

    @abstractmethod
    def encloses(self, shape):
        pass

    @abstractmethod
    def compute_area_intersection(self, shape):
        pass

    @abstractmethod
    def union_bounds(self, shape):
        pass


def bounds_union(shapes):
    if not shapes:
        return None
    
    result = shapes[0]
    
    for s in shapes[1:]:
        if result is None:
            result = s
        else:
            result = result.union_bounds(s)
            
    return result

