# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class SizeSelector:
    def __init__(self, size: 'Size') -> None:
        self.size = size

    def test(self, creature: object) -> bool:
        return getattr(creature, 'getSize', lambda: None())() == self.size
