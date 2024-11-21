Here is the translation of the Java code to Python:

```Python
class HandlerMap:
    def __init__(self):
        self.map = {}

    def put(self, cls: type[T], handler: callable[[U, A], R]) -> callable[[U, A], R]:
        return self.map.setdefault(cls, lambda u, a: handler(u, a))

    def put_void(self, cls: type[U], handler: BiConsumer[U, A]) -> callable[[U, A], None]:
        return self.put(cls, lambda u, a: handler.accept(u, a) or None)

    def handle(self, t: T, a: A) -> R:
        function = self.map.get(type(t))
        if function is not None:
            return function(t, a)
        raise ValueError(f"No handler for {t}")
```

Note that Python does not have direct equivalents to Java's generics or type parameters. Instead, we use the `type` hinting system and dynamic typing to achieve similar functionality.

Also note that in Python, you don't need to explicitly specify return types like you do in Java. The function will automatically return whatever value is assigned to it (or None if no explicit return statement is given).