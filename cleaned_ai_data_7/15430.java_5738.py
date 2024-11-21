import numpy as np
from djl.translate import Transform
from ai.djl.ndarray import NDArray

class RandomResizedCrop(Transform):
    def __init__(self, width: int, height: int, min_area_scale: float, max_area_scale: float,
                 min_aspect_ratio: float, max_aspect_ratio: float):
        self.width = width
        self.height = height
        self.min_area_scale = min_area_scale
        self.max_area_scale = max_area_scale
        self.min_aspect_ratio = min_aspect_ratio
        self.max_aspect_ratio = max_aspect_ratio

    def transform(self, array: NDArray) -> NDArray:
        return ndimage.random_resized_crop(array, self.width, self.height,
                                            self.min_area_scale, self.max_area_scale,
                                            self.min_aspect_ratio, self.max_aspect_ratio)
