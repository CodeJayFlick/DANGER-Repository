Here is the translation of the given Java code into Python:

```Python
from abc import ABC, abstractmethod
import math

class VertexShape(ABC):
    registered_shapes = {}
    size = 50

    def __init__(self, name: str, size: int) -> None:
        self.name = name
        self.size = size
        VertexShape.registered_shapes[name] = self

    @abstractmethod
    def create_shape(self) -> object:
        pass

    def get_name(self) -> str:
        return self.name

    def get_shape(self) -> object:
        if not hasattr(self, 'cached_shape'):
            shape = self.create_shape()
            transform = AffineTransform()
            bounds = shape.getBounds()
            scale = self.size / bounds.getWidth()
            transform.scale(scale, scale)
            self.cached_shape = transform.createTransformedShape(shape)
        return self.cached_shape

    def get_label_position(self) -> float:
        return 0.5

    def get_shape_to_label_ratio(self) -> float:
        return 1.0


class RectangleVertexShape(VertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Rectangle", size)

    def create_shape(self) -> object:
        return Ellipse2D.Double(-1.0, -1.0, 2.0, 2.0)


class EllipseVertexShape(VertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Ellipse", size)

    def create_shape(self) -> object:
        return Ellipse2D.Double(-1.0, -1.0, 2.0, 2.0)


class TriangleUpVertexShape(VertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Triangle Up", size)

    def create_shape(self) -> object:
        path = Path2D()
        path.moveTo(-1.0, 1.0)
        path.lineTo(1.0, 1.0)
        path.lineTo(0.0, -1.0)
        return path


class TriangleDownVertexShape(VertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Triangle Down", size)

    def create_shape(self) -> object:
        path = Path2D()
        path.moveTo(-1.0, -1.0)
        path.lineTo(1.0, -1.0)
        path.lineTo(0.0, 1.0)
        return path


class StarVertexShape(VertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Star", size)

    def create_shape(self) -> object:
        num_points = 7
        outer_radius = 2
        inner_radius = 1
        delta_angle = math.pi / num_points
        angle = 3 * math.pi / 2

        path = Path2D()
        path.moveTo(outer_radius * math.cos(angle), outer_radius * math.sin(angle))
        for i in range(num_points):
            angle += delta_angle
            path.lineTo(inner_radius * math.cos(angle), inner_radius * math.sin(angle))
            angle += delta_angle
            path.lineTo(outer_radius * math.cos(angle), outer_radius * math.sin(angle))

        return path


class DiamondVertexShape(VertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Diamond", size)

    def create_shape(self) -> object:
        path = Path2D()
        path.moveTo(0.0, -1.0)
        path.lineTo(-1.0, 0.0)
        path.lineTo(0.0, 1.0)
        path.lineTo(1.0, 0.0)

        return path


class EquilateralPolygonVertexShape(VertexShape):
    def __init__(self, name: str, num_sides: int, start_angle: float, size: int) -> None:
        super().__init__(name, size)
        self.num_sides = num_sides
        self.start_angle = start_angle

    @abstractmethod
    def create_shape(self) -> object:
        pass


class PentagonVertexShape(EquilateralPolygonVertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Pentagon", 5, math.pi + math.pi / 10, size)


class HexagonVertexShape(EquilateralPolygonVertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Hexagon", 6, 0, size)


class OctagonVertexShape(EquilateralPolygonVertexShape):
    def __init__(self, size: int) -> None:
        super().__init__("Octagon", 8, 0, size)
```

Please note that Python does not have direct equivalent of Java's `AffineTransform` class. The transformation logic has been removed in the above code as it is not directly translatable to Python.