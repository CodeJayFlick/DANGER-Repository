class SkriptColor:
    def __init__(self, dye_color: 'DyeColor', chat_color: 'ChatColor'):
        self.chat = chat_color
        self.dye = dye_color

    @property
    def as_bukkit_color(self):
        return self.dye.color

    @property
    def as_dye_color(self):
        return self.dye

    @property
    def name(self):
        if self.adjective:
            return str(self.adjective)
        else:
            return self.__class__.__name__

    def serialize(self) -> 'Fields':
        from yggdrasil import Fields
        return Fields(self, Variables.yggdrasil)

    def deserialize(self, fields: 'Fields'):
        try:
            self.dye = fields.get_object('dye', DyeColor)
            self.chat = fields.get_object('chat', ChatColor)
            self.adjective = fields.get_object('adjective', Adjective)
        except StreamCorruptedException:
            pass

    def get_formatted_chat(self):
        return f'{self.chat}'

    @property
    def adjective(self):
        return self._adjective

    @adjective.setter
    def adjective(self, value: 'Adjective'):
        self._adjective = value

    @staticmethod
    def from_name(name: str) -> 'SkriptColor':
        if name:
            for color in SkriptColors.values():
                if color.name().lower() == name.lower():
                    return color
        return None

    @staticmethod
    def from_dye_color(dye_color: 'DyeColor') -> 'SkriptColor':
        for color in SkriptColors.values():
            if color.as_dye_color() == dye_color:
                return color
        return None

    @staticmethod
    def from_bukkit_color(bukkit_color: 'BukkitColor') -> 'SkriptColor':
        for color in SkriptColors.values():
            if color.as_bukkit_color() == bukket_color:
                return color
        return None


class DyeColor:
    def __init__(self, dye_data: int):
        self.dye_data = dye_data

    @property
    def get_wool_data(self) -> int:
        return 15 - self.dye_data

    @property
    def get_dye_data(self) -> int:
        return self.dye_data


class ChatColor:
    pass


class Adjective:
    def __init__(self, node: str):
        self.node = node

    def to_string(self, start_index: int, end_index: int) -> str:
        if start_index < 0 or end_index > len(self.node):
            return ''
        else:
            return self.node[start_index:end_index]


class BukkitColor:
    pass


# This is a dictionary-like object that maps color names to SkriptColors
SkriptColors = {}

def main():
    # Initialize the colors here, this will be done in your actual code.
    for dye_color in [DyeColor(0), DyeColor(1)]:
        for chat_color in [ChatColor(), ChatColor()]:
            color_name = f'{dye_color.dye_data}_{chat_color}'
            SkriptColors[color_name] = SkriptColor(dye_color, chat_color)


if __name__ == '__main__':
    main()
