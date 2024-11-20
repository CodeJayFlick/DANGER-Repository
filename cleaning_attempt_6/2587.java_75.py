class TraceLabelSymbolView:
    def add(self, lifespan: range, thread: str, address: int, name: str, parent: str, source: str) -> dict:
        return {"symbol": f"Trace Label Symbol {name}", "lifespan": lifespan, "thread": thread, "address": address}

    def create(self, snap: int, thread: str, address: int, name: str, parent: str, source: str) -> dict:
        return self.add(range(snap), thread, address, name, parent, source)
