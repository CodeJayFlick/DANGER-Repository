class ImageClassificationDataset:
    def __init__(self):
        pass

    @abstractmethod
    def get_class_number(self, index: int) -> int:
        raise NotImplementedError("Method not implemented")

    def get(self, manager, index: int) -> dict:
        data = self.get_record_image(manager, index)
        label = {f"class_{index}": self.get_class_number(index)}
        return {"data": data, "label": label}

    @abstractmethod
    def get_classes(self) -> list[str]:
        raise NotImplementedError("Method not implemented")

    def make_translator(self):
        pipeline = []
        
        # Resize the image if the image size is fixed
        width = self.get_image_width()
        height = self.get_image_height()
        if width and height:
            pipeline.append({"Resize": {"width": int(width), "height": int(height)}})
        pipeline.append({"ToTensor": {}})
        
        return {
            "translator": "ImageClassificationTranslator",
            "synset": self.get_classes(),
            "pipeline": pipeline
        }

    def get_record_image(self, manager: dict, index: int) -> list[dict]:
        raise NotImplementedError("Method not implemented")

    def get_image_width(self):
        raise NotImplementedError("Method not implemented")

    def get_image_height(self):
        raise NotImplementedError("Method not implemented")
