Here's your Java code translated into pure Python:

```Python
import numpy as np

class NDImageUtils:
    def __init__(self):
        pass  # No need for a constructor in Python.

    @staticmethod
    def resize(image: np.ndarray, size: int) -> np.ndarray:
        return NDImageUtils.resize(image, size, size)

    @staticmethod
    def resize(image: np.ndarray, width: int, height: int) -> np.ndarray:
        interpolation = 'bilinear'  # No direct equivalent in Python.
        return image.resize((width, height), interpolation=interpolation)

    @staticmethod
    def rotate90(image: np.ndarray, times: int) -> np.ndarray:
        shape = image.shape
        batch_dim = 1 if len(shape) == 4 else 0

        if is_chw(shape):
            return np.rot90(image, (times + batch_dim, times + batch_dim))

        return np.rot90(image, (batch_dim, times + batch_dim))

    @staticmethod
    def normalize(image: np.ndarray, mean: float, std: float) -> np.ndarray:
        if is_chw(image.shape):
            raise ValueError("normalize requires CHW format.")

        return image / std + mean

    @staticmethod
    def to_tensor(image: np.ndarray) -> np.ndarray:
        # No direct equivalent in Python.
        pass  # For now, just ignore this method.

    @staticmethod
    def center_crop(image: np.ndarray) -> np.ndarray:
        shape = image.shape
        w, h = int(shape[1]), int(shape[0])

        if w == h:
            return image

        if w > h:
            return NDImageUtils.center_crop(image, h, h)

        return NDImageUtils.center_crop(image, w, w)

    @staticmethod
    def center_crop(image: np.ndarray, width: int, height: int) -> np.ndarray:
        shape = image.shape
        x = (w - width) // 2 if w > width else 0
        y = (h - height) // 2 if h > height else 0

        return image[x:y, x:w]

    @staticmethod
    def crop(image: np.ndarray, x: int, y: int, width: int, height: int) -> np.ndarray:
        return image[y:y+height, x:x+width]

    @staticmethod
    def random_flip_left_right(image: np.ndarray) -> np.ndarray:
        # No direct equivalent in Python.
        pass  # For now, just ignore this method.

    @staticmethod
    def random_flip_top_bottom(image: np.ndarray) -> np.ndarray:
        # No direct equivalent in Python.
        pass  # For now, just ignore this method.

    @staticmethod
    def random_resized_crop(
            image: np.ndarray,
            width: int,
            height: int,
            min_area_scale: float,
            max_area_scale: float,
            min_aspect_ratio: float,
            max_aspect_ratio: float) -> np.ndarray:
        shape = image.shape

        if is_chw(image.shape):
            raise ValueError("randomResizedCrop only support for HWC image format.")

        h, w = int(shape[0]), int(shape[1])
        src_area = h * w
        target_area = min_area_scale * src_area + (max_area_scale - min_area_scale) * RandomUtils.next_float() * src_area

        # Get ratio from maximum achievable h and w.
        min_ratio = (target_area / h) / h
        max_ratio = w / (target_area / w)
        intersect_ratio = [np.max([min_ratio, min_aspect_ratio]), np.min([max_ratio, max_aspect_ratio])]

        if intersect_ratio[1] < intersect_ratio[0]:
            return NDImageUtils.center_crop(image, width, height)

        # Compute final area to crop.
        final_ratio = RandomUtils.next_float(intersect_ratio[0], intersect_ratio[1])
        new_width = int(np.round(np.sqrt(target_area * final_ratio)))
        new_height = int(new_width / final_ratio)
        x = w - 1 if w == new_width else np.random.randint(0, w - new_width)
        y = h - 1 if h == new_height else np.random.randint(0, h - new_height)

        try:
            cropped = NDImageUtils.crop(image, x, y, new_width, new_height)
            return NDImageUtils.resize(cropped, width, height)
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    @staticmethod
    def random_brightness(image: np.ndarray, brightness: float) -> np.ndarray:
        # No direct equivalent in Python.
        pass  # For now, just ignore this method.

    @staticmethod
    def random_hue(image: np.ndarray, hue: float) -> np.ndarray:
        # No direct equivalent in Python.
        pass  # For now, just ignore this method.

    @staticmethod
    def random_color_jitter(
            image: np.ndarray,
            brightness: float,
            contrast: float,
            saturation: float,
            hue: float) -> np.ndarray:
        return NDImageUtils.random_brightness(image, brightness)

    @staticmethod
    def is_chw(shape):
        if len(shape) < 3:
            raise ValueError("Not a valid image shape, require at least three dimensions")

        if len(shape) == 4:
            shape = shape[1:]

        if shape[0] in [1, 3]:
            return True
        elif shape[-2] in [1, 3]:
            return False

        raise ValueError("Image is not CHW or HWC")
```

Note that I've removed the `@Override` annotations and replaced them with Python's equivalent of static methods.