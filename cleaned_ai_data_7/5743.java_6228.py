import xml.etree.ElementTree as ET
from collections import defaultdict
from enum import Enum

class QUADRANT(Enum):
    TL = 1
    TR = 2
    BL = 3
    BR = 4


class FileIconService:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls._instance, cls):
            cls._instance = super(FileIconService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.file_ext_to_icon_name = defaultdict(str)
        self.file_substr_to_icon_name = {}
        self.overlay_name_to_icon_name = {}
        self.overlay_name_to_quad = {}
        self.default_icon_path = "images/famfamfam_silk_icons_v013/page_white.png"
        self.max_ext_level = 1

    def make_key(self, key: str, overlays: list) -> str:
        sb = StringBuilder()
        sb.append(key)
        for o in overlays:
            if not o or not o.strip():
                continue
            sb.append(o).append("__")
        return sb.toString()

    def get_cached_icon(self, key: str, path: str, overlays: tuple) -> object:
        cached_icon = self.icon_key_to_icon.get(key)
        if cached_icon is None:
            cached_icon = ResourceManager.load_image(path)
            for overlay in overlays:
                if not overlay or not overlay.strip():
                    continue
                quad = self.overlay_name_to_quad[overlay]
                expected_width, expected_height = int(cached_icon.width / 2), int(
                    cached_icon.height / 2)

                used_quads = set()
                icon_builder = MultiIconBuilder(cached_icon)
                for o in overlays:
                    if not o or not o.strip():
                        continue
                    overlay_path = self.overlay_name_to_icon_name[overlay]
                    if overlay_path is None or quad is None:
                        continue

                    if quad in used_quads:
                        print(f"File icon already contains an overlay at {quad}")
                    else:
                        used_quads.add(quad)

                    overlay_icon = ResourceManager.load_image(overlay_path)
                    icon_builder.add_icon(overlay_icon, expected_width,
                                           expected_height, quad)

                cached_icon = icon_builder.build()
            self.icon_key_to_icon[key] = cached_icon
        return cached_icon

    def get_image(self, file_name: str, overlays: tuple) -> object:
        if not hasattr(self, 'file_ext_to_icon_name'):
            self.load()

        for ext_level in range(1, self.max_ext_level + 1):
            substr = FSUtilities.get_extension(file_name, ext_level)
            if substr is None:
                break
            path = self.file_ext_to_icon_name[substr]
            if path:
                return self.get_cached_icon(substr, path, overlays)

        for substr in self.file_substr_to_icon_name.keys():
            if file_name.find(substr) != -1:
                return self.get_cached_icon("####" + substr,
                                             self.file_substr_to_icon_name[substr], overlays)
        # Return default icon for generic file
        return self.get_cached_icon("", self.default_icon_path, overlays)

    def load(self):
        if not hasattr(self, 'file_ext_to_icon_name'):
            try:
                tree = ET.parse(str(self.xml_file))
                root = tree.getroot()
                for child in root.findall('.//{http://www.ghidra.com/file-extension}file_extension'):
                    extension = child.attrib['extension']
                    icon_path = child.attrib['icon']
                    if not self.file_ext_to_icon_name[extension]:
                        add_substr_mapping(extension, icon_path)
                    else:
                        add_ext_mapping(extension, icon_path)

                for child in root.findall('.//{http://www.ghidra.com/file-overlay}file_overlay'):
                    name = child.attrib['name']
                    icon_path = child.attrib['icon']
                    quadrant = QUADRANT[child.attrib.get('quadrant', 'LR')]
                    self.overlay_name_to_icon_name[name] = icon_path
                    self.overlay_name_to_quad[name] = quadrant

            except ET.ParseError as e:
                print(f"Error reading file icon data: {e}")

    def add_substr_mapping(self, substr: str, icon_path: str):
        self.file_substr_to_icon_name[substr] = icon_path

    def add_ext_mapping(self, ext: str, icon_path: str):
        self.file_ext_to_icon_name[ext] = icon_path
        self.max_ext_level = max(self.max_ext_level, count_ext_level(ext))

    def count_ext_level(self, ext: str) -> int:
        return sum(1 for char in ext if char == '.')

# Usage example:

class ResourceManager:
    @staticmethod
    def load_image(path):
        # Load image from path
        pass

class FSUtilities:
    @staticmethod
    def get_extension(file_name: str, level: int) -> str:
        # Get extension of file name at given level
        pass


# Example usage:

file_icon_service = FileIconService()
image = file_icon_service.get_image("example.txt", ("overlay1", "overlay2"))
