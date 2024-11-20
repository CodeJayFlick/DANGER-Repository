import os
from collections import defaultdict, OrderedDict

class IconMap:
    _icon_map = create_icon_map()

    @staticmethod
    def put(name: str, icon_url: str) -> None:
        IconMap._icon_map[name] = icon_url

    @staticmethod
    def remove(name: str) -> str | None:
        return IconMap._icon_map.pop(name, None)

    @staticmethod
    def get(name: str) -> str | None:
        return IconMap._icon_map.get(name)

    @staticmethod
    def get_icon_names() -> list[str]:
        return sorted(list(IconMap._icon_map.keys()))

    @staticmethod
    def get_icons() -> list[str]:
        return sorted(list(IconMap._icon_map.values()))

    @staticmethod
    def load(icon_map: dict) -> None:
        images = ResourceManager.get_tool_images()
        for filename in images:
            pos = filename.rfind('/')
            if pos >= 0:
                filename = filename[pos + 1:]
            if not icon_map.get(filename):
                icon_map[filename] = os.path.join('resources', 'images', filename)
