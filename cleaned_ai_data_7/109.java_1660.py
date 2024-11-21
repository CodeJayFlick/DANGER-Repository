class MemviewMap:
    def __init__(self, elems: int, pixels: int):
        self.max = sz = elems
        if pixels == 0:
            self.elements_per_pixel = 0
        else:
            self.elements_per_pixel = elems / pixels
        self.multiplier = 1.0

    def create_mapping(self, mult: float) -> None:
        self.multiplier = mult

    def get_offset(self, pixel: int) -> int:
        return round(pixel * self.elements_per_pixel / self.multiplier)

    def get_pixel(self, offset: int) -> int:
        if offset < 0:
            offset = self.max
        doffset = offset * self.multiplier / self.elements_per_pixel
        return round(doffset)

    def get_size(self) -> int:
        return self.get_pixel(self.max)

    def get_multiplier(self) -> float:
        return self.multiplier

    def get_original_elem_per_pixel(self) -> float:
        return self.elements_per_pixel
