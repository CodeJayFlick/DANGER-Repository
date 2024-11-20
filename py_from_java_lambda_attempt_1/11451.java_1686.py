Here is the translation of the given Java code into equivalent Python:

```Python
class SleighSubtableTraversal:
    def __init__(self, sub):
        self.sub = sub

    def traverse(self, visitor):
        result = self._traverse(self.sub.get_decision_node(), visitor)
        if result == 'finished':
            return 'finished'
        else:
            return result

    def _traverse(self, node, visitor):
        for pattern in node.get_patterns():
            for constructor in node.get_constructors():
                result = visitor.visit(pattern, constructor)
                if result != 'continue':
                    return result
        for child_node in node.get_children():
            result = self._traverse(child_node, visitor)
            if result != 'continue':
                return result
        return 'continue'
```

Note that Python does not have an exact equivalent to Java's `VisitorResults` interface. Instead, we've used strings ('finished', 'continue') as indicators for the end of traversal and continuation respectively.

Also note that in Python, it is conventional to use underscores instead of camelCase when naming private methods (i.e., `_traverse`).