class ImageDataset:
    def __init__(self):
        pass

    @property
    def flag(self):
        return self._flag

    @flag.setter
    def flag(self, value):
        self._flag = value

    def get_record_image(self, manager, index) -> 'NDArray':
        image = self.get_image(index).to_ndarray(manager, self.flag)

        # Resize the image if the image size is fixed
        width = self.image_width()
        height = self.image_height()

        if width and height:
            image = NDImageUtils.resize(image, width, height)
        return image

    def get_image(self, index) -> 'Image':
        raise NotImplementedError("get_image must be implemented")

    @property
    def image_channels(self):
        return self.flag.num_channels

    @property
    def image_width(self) -> Optional[int]:
        raise NotImplementedError("image_width must be implemented")

    @property
    def image_height(self) -> Optional[int]:
        raise NotImplementedError("image_height must be implemented")


class BaseBuilder:
    def __init__(self):
        self._flag = Image.Flag.COLOR

    @property
    def flag(self):
        return self._flag

    @flag.setter
    def flag(self, value: 'Image.Flag'):
        self._flag = value
        return self


class Optional(int):
    pass


def resize(image, width, height) -> 'NDArray':
    # This function should be implemented based on the actual resizing logic.
    raise NotImplementedError("resize must be implemented")


class NDArray:
    def to_ndarray(self, manager, flag):
        # This method should be implemented based on the actual conversion logic.
        raise NotImplementedError("to_ndarray must be implemented")
