Here is the translation of the Java code into Python:

```Python
import numpy as np
from PIL import Image
import random

class NDImageUtils:
    @staticmethod
    def normalize(image, mean, std):
        normalized = (image - mean) / std
        return normalized

    @staticmethod
    def to_tensor(image):
        image = image.astype(np.float32)
        image /= 255.0
        image = np.transpose(image, [2, 1, 0])
        return image

    @staticmethod
    def resize(image, height=None, width=None, interpolation=Image.BILINEAR):
        if height is None and width is None:
            raise ValueError("At least one of the dimensions must be specified")
        
        img = Image.fromarray((image * 255).astype(np.uint8))
        img = img.resize((width, height), method=getattr(Image, f"{interpolation}"))
        return np.array(img) / 255.0

    @staticmethod
    def crop(image, x1, y1, x2, y2):
        if not (x1 >= 0 and x2 <= image.shape[1] and y1 >= 0 and y2 <= image.shape[2]):
            raise ValueError("Crop coordinates out of bounds")
        
        return image[:, :, y1:y2, x1:x2]

    @staticmethod
    def random_resized_crop(image, height=224, width=None, aspect_ratio_range=(3/4, 4/3), area_range=(0.05, 1)):
        w = int(height * (aspect_ratio_range[1] - aspect_ratio_range[0]) / (aspect_ratio_range[0] + aspect_ratio_range[1]))
        
        if random.random() < 0.5:
            x1 = np.clip(np.round(random.uniform(0, image.shape[2]-w)), 0, image.shape[2]-w)
            y1 = 0
            w = min(w, image.shape[2] - x1)
        else:
            x1 = 0
            if random.random() < 0.5:
                h = int(height * (aspect_ratio_range[1] - aspect_ratio_range[0]) / (aspect_ratio_range[0] + aspect_ratio_range[1]))
                y1 = np.clip(np.round(random.uniform(0, image.shape[1]-h)), 0, image.shape[1]-h)
            else:
                h = min(height, image.shape[1])
                y1 = 0
        
        return NDImageUtils.crop(image, x1, y1, x1+w, y1+h)

    @staticmethod
    def random_flip_left_right(image):
        if random.random() < 0.5:
            return np.fliplr(image)
        else:
            return image

    @staticmethod
    def random_flip_top_bottom(image):
        if random.random() < 0.5:
            return np.flipud(image)
        else:
            return image

    @staticmethod
    def random_brightness(image, alpha=1.0):
        return (image * alpha).clip(0, 255)

    @staticmethod
    def random_hue(image, delta=18):
        image = image.astype(np.uint8)
        image += np.array([[[k + int(delta)] for k in range(256)]]).astype(np.uint8)
        image %= 256
        return (image / 255.0)

    @staticmethod
    def random_color_jitter(image, brightness=1.0, contrast=1.0, saturation=1.0, hue=1.0):
        if random.random() < 0.5:
            image = NDImageUtils.random_brightness(image, alpha=brightness)
            return (image * contrast).clip(0, 255) * saturation
        else:
            return image

# Example usage:

if __name__ == "__main__":
    manager = None
    try:
        # Create a new NDManager instance.
        manager = np.random.RandomState().new_base_manager()
        
        # Test the normalize function.
        image = manager.ones((3, 4, 2))
        mean = [0.3, 0.4, 0.5]
        std = [0.8, 0.8, 0.8]
        normalized_image = NDImageUtils.normalize(image, mean, std)
        
        # Test the to_tensor function.
        image = manager.random.uniform(0, 255, (3, 2))
        tensor_image = NDImageUtils.to_tensor(image)

    finally:
        if manager is not None:
            del manager
```

This Python code defines a class `NDImageUtils` with static methods that implement the same functionality as their Java counterparts. The example usage at the end demonstrates how to use these functions.