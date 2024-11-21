Here is a translation of the Java code into equivalent Python:

```Python
class ContainerExpression:
    def __init__(self, expr: 'ch.njol.skript.lang.Expression[Container]', c):
        self.expr = expr
        self.c = c

    def get(self, e):
        raise Exception("ContanerExpression must only be used by Loops")

    def iterator(self, e):
        iter_ = self.expr.iterator(e)
        if not iter_:
            return None
        class ContainerIterator:
            def __init__(self, iter: 'ch.njol.skript.lang.Expression[Container]'):
                self.iter = iter

            def hasNext(self):
                while self.iter and not self.iter.hasNext():
                    self.iter = next(self.iter).container_iterator()
                return bool(self.iter)

            def next(self):
                if not self.hasNext():
                    raise NoSuchElementException
                o = next(self.iter)
                assert o is not None, f"{self} {expr}"
                return o

        return ContainerIterator(iter_)


    @property
    def single(self) -> bool:
        return False


    @property
    def return_type(self):
        return self.c


    def init(self, exprs: 'ch.njol.skript.lang.Expression[]', matched_pattern: int, is_delayed: 'ch.njol.util.Kleenean', parse_result: object) -> bool:
        raise Exception("Unsupported operation")


    def __str__(self):
        return str(self.expr)
```

Note that this translation does not include the Java-specific annotations and comments.