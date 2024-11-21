Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABCMeta, abstractmethod

class AbstractRectangle2DQuery(metaclass=ABCMeta):
    def __init__(self, r1: 'NS', r2: 'NS', space: 'EuclideanSpace2D[X, Y]', direction: 'Rectangle2DDirection'):
        self.r1 = r1
        self.r2 = r2
        self.space = space
        self.direction = direction

    @abstractmethod
    def create(self, ir1: 'NS', ir2: 'NS', new_direction: 'Rectangle2DDirection') -> 'Q':
        pass

class QueryFactory(metaclass=ABCMeta):
    @abstractmethod
    def create(self, r1: 'NS', r2: 'NS', direction: 'Rectangle2DDirection') -> 'Q':
        pass

def intersecting(rect: 'NS', direction: 'Rectangle2DDirection', factory: 'QueryFactory') -> 'Q':
    full = rect.get_space().get_full()
    r1 = rect.immutable(full.x1, rect.x2, full.y1, rect.y2)
    r2 = rect.immutable(rect.x1, full.x2, rect.y1, full.y2)
    return factory.create(r1, r2, direction)

def enclosing(rect: 'NS', direction: 'Rectangle2DDirection', factory: 'QueryFactory') -> 'Q':
    full = rect.get_space().get_full()
    r1 = rect.immutable(full.x1, rect.x1, full.y1, rect.y1)
    r2 = rect.immutable(rect.x2, full.x2, rect.y2, full.y2)
    return factory.create(r1, r2, direction)

def enclosed(rect: 'NS', direction: 'Rectangle2DDirection', factory: 'QueryFactory') -> 'Q':
    full = rect.get_space().get_full()
    r1 = rect.immutable(rect.x1, full.x2, rect.y1, full.y2)
    r2 = rect.immutable(full.x1, rect.x2, full.y1, rect.y2)
    return factory.create(r1, r2, direction)

def equal_to(rect: 'NS', direction: 'Rectangle2DDirection', factory: 'QueryFactory') -> 'Q':
    r1 = rect.immutable(rect.x1, rect.x1, rect.y1, rect.y1)
    r2 = rect.immutable(rect.x2, rect.x2, rect.y2, rect.y2)
    return factory.create(r1, r2, direction)

class QueryInclusion:
    NONE = 0
    SOME = 1
    ALL = 2

def terminate_early_data(shape: 'DS') -> bool:
    return terminate_early_node(shape.get_bounds())

def terminate_early_node(shape: 'NS') -> bool:
    if shape.direction == Rectangle2DDirection.LEFTMOST:
        return shape.space.compare_x(shape.x1, r2.x2) > 0
    elif shape.direction == Rectangle2DDirection.RIGHTMOST:
        return shape.space.compare_x(shape.x2, r1.x1) < 0
    elif shape.direction == Rectangle2DDirection.BOTTOMMOST:
        return shape.space.compare_y(shape.y1, r2.y2) > 0
    elif shape.direction == Rectangle2DDirection.TOPMOST:
        return shape.space.compare_y(shape.y2, r1.y1) < 0

def test_node(shape: 'NS') -> QueryInclusion:
    if shape.space.compare_x(shape.x1, r1.x2) > 0 or shape.space.compare_x(shape.x1, r2.x2) > 0:
        return QueryInclusion.NONE
    elif shape.space.compare_y(shape.y1, r1.y2) > 0 or shape.space.compare_y(shape.y1, r2.y2) > 0:
        return QueryInclusion.NONE

    if shape.space.compare_x(shape.x2, r2.x1) < 0 or shape.space.compare_x(shape.x2, r1.x1) < 0:
        return QueryInclusion.SOME
    elif shape.space.compare_y(shape.y2, r2.y1) < 0 or shape.space.compare_y(shape.y2, r1.y1) < 0:
        return QueryInclusion.SOME

    # At this point, we know all smaller children must satisfy the query
    return QueryInclusion.ALL

def create_bounds_comparator() -> 'Comparator[NS]':
    if direction == Rectangle2DDirection.LEFTMOST:
        return Comparator.comparing(lambda x: x.x1, key=shape.space.compare_x)
    elif direction == Rectangle2DDirection.RIGHTMOST:
        return Comparator.comparing(lambda x: x.x2, key=lambda a, b: shape.space.compare_x(b, a))
    elif direction == Rectangle2DDirection.BOTTOMMOST:
        return Comparator.comparing(lambda x: x.y1, key=shape.space.compare_y)
    elif direction == Rectangle2DDirection.TOPMOST:
        return Comparator.comparing(lambda x: x.y2, key=lambda a, b: shape.space.compare_y(b, a))

def get_direction() -> 'Rectangle2DDirection':
    if direction is None:
        return Rectangle2DDirection.LEFTMOST
    else:
        return direction

def and_(query: 'Q') -> 'Q':
    ir1 = r1.intersection(query.r1)
    ir2 = r2.intersection(query.r2)
    return query.create(ir1, ir2, query.direction if query.direction is not None else self.direction)

def starting(new_direction: 'Rectangle2DDirection') -> 'Q':
    return create(r1, r2, new_direction)
```

Note that this translation assumes the following:

- The Java code has been modified to use Python's type hinting system.
- All classes and methods have been renamed according to PEP 8 conventions (e.g., `AbstractRectangle2DQuery` instead of `abstract class AbstractRectangle2DQuery`, etc.).
- Some Java-specific constructs, such as the `@Override` annotation or the `throws new AssertionError()` statement, are not present in Python.
- The code has been formatted according to PEP 8 conventions (e.g., consistent indentation and line length).