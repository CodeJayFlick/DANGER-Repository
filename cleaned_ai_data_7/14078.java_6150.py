class Rectangle:
    def __init__(self, left: int, top: int, right: int, bottom: int):
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom

    @property
    def get_left(self) -> int:
        return self.left

    @property
    def get_right(self) -> int:
        return self.right

    @property
    def get_top(self) -> int:
        return self.top

    @property
    def get_bottom(self) -> int:
        return self.bottom

    def intersectsWith(self, r: 'Rectangle') -> bool:
        if (r.get_left() > self.right or r.get_right() < self.left or 
            r.get_top() > self.bottom or r.get_bottom() < self.top):
            return False
        else:
            return True

    def __str__(self) -> str:
        return f"({self.left},{self.top},{self.right},{self.bottom})"
