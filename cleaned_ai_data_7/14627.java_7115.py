class ObjectPool(T):
    def __init__(self):
        self.available = set()
        self.in_use = set()

    def create(self) -> T:
        # This method should be implemented by subclasses
        pass

    def check_out(self) -> T:
        if not self.available:
            instance = self.create()
            self.available.add(instance)
        return next(iter(self.available))
        self.available.remove(next(iter(self.available)))
        self.in_use.add(next(iter(self.available)))

    def check_in(self, instance: T):
        self.in_use.remove(instance)
        self.available.add(instance)

    def __str__(self) -> str:
        return f"Pool available={len(self.available)} inUse={len(self.in_use)}"
