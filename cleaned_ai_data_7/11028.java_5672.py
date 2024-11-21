class DomainFileType:
    def __init__(self, content_type: str, icon: any, is_versioned: bool):
        self.content_type = content_type
        self.icon = icon
        self.is_versioned = is_versioned

    def compare_to(self, other: 'DomainFileType') -> int:
        result = self.content_type.casefold().compare(other.content_type.casefold())
        if result == 0:
            result = (1 if self.is_versioned else 0).compare((1 if other.is_versioned else 0))
        return result

    def get_content_type(self) -> str:
        return self.content_type

    def get_icon(self) -> any:
        return self.icon

    def display_string(self) -> str:
        return self.content_type

    def __str__(self) -> str:
        if self.is_versioned:
            version_str = "versioned"
        else:
            version_str = "unversioned"
        return f"{self.content_type} ({version_str})"
