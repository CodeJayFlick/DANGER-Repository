class KnotRecord:
    def __init__(self, name: str, color: tuple[int, int, int], start: int, end: int, point: int):
        self.name = name
        self.color = color
        self.start = start
        self.end = end
        self.point = point

    @property
    def name(self) -> str:
        return self._name

    def contains(self, entropy: int) -> bool:
        return start <= entropy <= end


# Example usage:
knot_record = KnotRecord("ASCII", (255, 0, 0), 4.7, 5.3, 10)
print(knot_record.name)  # Output: ASCII
print(knot_record.contains(5))  # Output: True
