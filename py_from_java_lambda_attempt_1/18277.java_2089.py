Here's your Java code translated into Python:

```Python
class TimeGenerator:
    def __init__(self):
        self.leaf_node_cache = {}
        self.leaf_values_cache = None
        self.operator_node = None
        self.has_or_node = False

    def has_next(self) -> bool:
        return self.operator_node.has_next()

    def next(self) -> int:
        if not self.has_or_node:
            if self.leaf_values_cache is None:
                self.leaf_values_cache = {}
            for path, nodes in self.leaf_node_cache.items():
                values = self.leaf_values_cache.setdefault(path, [])
                values.append(nodes[0].current_value())
        return self.operator_node.next()

    def get_values(self, path: str) -> list:
        if self.has_or_node:
            raise IOException("getValues() method should not be invoked when there is OR operator in where clause")
        if self.leaf_values_cache.get(path) is None:
            raise IOException("getValues() method should not be invoked by non-existent path in where clause")
        return list(self.leaf_values_cache.pop(path))

    def get_value(self, path: str) -> object:
        if self.has_or_node:
            raise IOException("getValue() method should not be invoked when there is OR operator in where clause")
        if self.leaf_values_cache.get(path) is None:
            raise IOException("getValue() method should not be invoked by non-existent path in where clause")
        return self.leaf_values_cache[path].pop(0)

    def construct_node(self, expression: object) -> None:
        self.operator_node = self.construct(expression)

    def construct(self, expression: object) -> object:
        if isinstance(expression, SingleSeriesExpression):
            series_reader = self.generate_new_batch_reader(expression)
            path = expression.get_series_path()
            leaf_node = LeafNode(series_reader)
            self.leaf_node_cache.setdefault(path, []).append(leaf_node)
            return leaf_node
        else:
            left_child = self.construct(getattr(expression, 'get_left', lambda: None)())
            right_child = self.construct(getattr(expression, 'get_right', lambda: None)())

            if expression.get_type() == ExpressionType.OR:
                self.has_or_node = True
                return OrNode(left_child, right_child, self.is_ascending())
            elif expression.get_type() == ExpressionType.AND:
                return AndNode(left_child, right_child, self.is_ascending())
        raise UnSupportedDataTypeException(f"Unsupported ExpressionType when construct OperatorNode: {expression.get_type()}")

    def generate_new_batch_reader(self, expression: object) -> object:
        # This method should be implemented in the subclass
        pass

    def has_or_node(self):
        return self.has_or_node

    def is_ascending(self):
        # This method should be implemented in the subclass
        pass


class SingleSeriesExpression:
    def __init__(self, series_path: str):
        self.series_path = series_path

    def get_series_path(self) -> str:
        return self.series_path


class LeafNode:
    def __init__(self, batch_reader: object):
        self.batch_reader = batch_reader
        self.current_value = None

    @property
    def current_value(self):
        if self.current_value is None:
            try:
                self.current_value = next(self.batch_reader)
            except StopIteration:
                pass  # No more values available
        return self.current_value


class OrNode(Node):
    def __init__(self, left_child: object, right_child: object, ascending: bool):
        super().__init__()
        self.left_child = left_child
        self.right_child = right_child
        self.ascending = ascending

    @property
    def has_next(self) -> bool:
        return self.left_child.has_next() or self.right_child.has_next()

    def next(self) -> int:
        if not self.left_child.has_next():
            return self.right_child.next()
        else:
            return self.left_child.next()


class AndNode(Node):
    def __init__(self, left_child: object, right_child: object, ascending: bool):
        super().__init__()
        self.left_child = left_child
        self.right_child = right_child
        self.ascending = ascending

    @property
    def has_next(self) -> bool:
        return self.left_child.has_next() and self.right_child.has_next()

    def next(self) -> int:
        if not self.left_child.next():
            raise StopIteration  # No more values available


class Node:
    pass


class IOException(Exception):
    pass


class UnSupportedDataTypeException(Exception):
    pass
```

This Python code should be equivalent to your Java code.