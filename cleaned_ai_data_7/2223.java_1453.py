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
