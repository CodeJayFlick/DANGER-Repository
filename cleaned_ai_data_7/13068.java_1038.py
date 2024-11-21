class XmlElement:
    def get_level(self):
        pass  # Implement this method in your subclass

    def is_start(self):
        return False  # Default implementation; override in your subclass if needed

    def is_end(self):
        return False  # Default implementation; override in your subclass if needed

    def is_content(self):
        return False  # Default implementation; override in your subclass if needed

    @property
    def name(self):
        pass  # Implement this property getter in your subclass

    @property
    def attributes(self):
        raise NotImplementedError("Implement the 'attributes' property getter")

    def has_attribute(self, key):
        return False  # Default implementation; override in your subclass if needed

    def get_attribute(self, key):
        raise AttributeError(f"Attribute '{key}' not found")  # Default implementation; override in your subclass if needed

    @property
    def text(self):
        pass  # Implement this property getter in your subclass

    @property
    def column_number(self):
        return None  # Default implementation; override in your subclass if needed

    @property
    def line_number(self):
        return None  # Default implementation; override in your subclass if needed

    def set_attribute(self, key: str, value: str) -> None:
        raise NotImplementedError("Implement the 'set_attribute' method")
