Here is the translation of the Java code into Python:

```Python
class Aliases:
    def __init__(self):
        self.provider = None
        self.parser = None
        self.script_aliases = None
        self.item_singular = "item"
        self.item_plural = "items"
        self.item_gender = None
        self.block_singular = "block"
        self.block_plural = "blocks"
        self.block_gender = None

    def concatenate(self, *parts):
        if len(parts) < 2:
            return ""
        result = "".join(map(str, parts))
        while True:
            if not result.startswith("  "):
                break
            result = result.replace("   ", " ")
        return result.strip()

    @staticmethod
    def get_material_name_data(type):
        if type is None:
            return None
        # Check script aliases first
        if Aliases.script_aliases is not None and Aliases.script_aliases.provider.get_material_name(type) is not None:
            return Aliases.script_aliases.provider.get_material_name(type)
        # Then global aliases
        return Aliases.provider.get_material_name(type)

    @staticmethod
    def get_gender(item):
        name = Aliases.get_material_name_data(item)
        if name is not None and isinstance(name, str) and len(name) > 0:
            return name.lower().endswith("s")
        return -1

    @staticmethod
    def parse_alias(s):
        if s is None or s.strip() == "":
            return None
        if s.lower() == "all":
            return Aliases.everything()
        t = ItemType()
        types = s.split(", ")
        for type in types:
            if type is not None and len(type) > 0:
                try:
                    t.add(ItemData(Material.AIR))
                except Exception as e:
                    print(f"Error: {e}")
                    return None
        return t

    @staticmethod
    def parse_item_type(s):
        s = s.strip().lower()
        if s is None or len(s) == 0:
            return None
        t = ItemType()
        m = p_any.match(s)
        if m is not None and isinstance(m.group(1), str):
            s = m.group(1).strip()
        else:
            for c in "abcdefghijklmnopqrstuvwxyz":
                if s.startswith(c.lower()):
                    s = c + s[1:]
                    break
        return t

    @staticmethod
    def clear():
        Aliases.provider.clear_aliases()

    @staticmethod
    def load():
        try:
            start_time = time.time()
            Aliases.load_internal()
            print(f"Loaded {Aliases.provider.get_alias_count()} aliases in {(time.time() - start_time):.2f} seconds")
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def load_directory(dir):
        for f in os.listdir(dir):
            if not f.startswith("."):
                try:
                    name = f.lower()
                    if os.path.isdir(os.path.join(dir, f)):
                        Aliases.load_directory(os.path.join(dir, f))
                    elif f.endswith(".sk"):
                        config = Config(f, False, False, "=")
                        Aliases.load(config)
                except Exception as e:
                    print(f"Error: {e}")

    @staticmethod
    def load(file):
        try:
            with open(file) as f:
                config = Config(f.name, False, False, "=")
                Aliases.load(config)
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def get_minecraft_id(data):
        if Aliases.script_aliases is not None and isinstance(Aliases.script_aliases.provider.get_minecraft_id(data), str) and len(Aliases.script_aliases.provider.get_minecraft_id(data)) > 0:
            return Aliases.script_aliases.provider.get_minecraft_id(data)
        else:
            return Aliases.provider.get_minecraft_id(data)

    @staticmethod
    def get_related_entity(data):
        if Aliases.script_aliases is not None and isinstance(Aliases.script_aliases.provider.get_related_entity(data), EntityData) and data is not None:
            return Aliases.script_aliases.provider.get_related_entity(data)
        else:
            return Aliases.provider.get_related_entity(data)

class ScriptAliases:
    def __init__(self, provider):
        self.provider = provider
        self.parser = Aliases.create_parser(provider)

@staticmethod
def create_script_aliases():
    local_provider = Aliases.create_provider(10, Aliases.provider)
    return ScriptAliases(local_provider)

@staticmethod
def set_script_aliases(aliases):
    global script_aliases
    script_aliases = aliases

class ItemType:
    def __init__(self):
        self.types = []

    @staticmethod
    def everything():
        t = ItemType()
        t.add(ItemData(Material.AIR))
        return t

    def add(self, data):
        if isinstance(data, ItemData) and not any(isinstance(t, ItemData) for t in self.types):
            self.types.append(data)

    def get_types(self):
        return self.types

    @staticmethod
    def parse(s):
        s = s.strip().lower()
        if s is None or len(s) == 0:
            return None
        t = ItemType()
        m = p_any.match(s)
        if m is not None and isinstance(m.group(1), str):
            s = m.group(1).strip()
        else:
            for c in "abcdefghijklmnopqrstuvwxyz":
                if s.startswith(c.lower()):
                    s = c + s[1:]
                    break
        return t

    def set_to(self, type):
        self.types.clear()
        self.add(type)

class ItemData:
    def __init__(self, material):
        self.material = material
        self.is_anything = False

    @staticmethod
    def parse(s):
        s = s.strip().lower()
        if s is None or len(s) == 0:
            return None
        t = ItemType()
        m = p_any.match(s)
        if m is not None and isinstance(m.group(1), str):
            s = m.group(1).strip()
        else:
            for c in "abcdefghijklmnopqrstuvwxyz":
                if s.startswith(c.lower()):
                    s = c + s[1:]
                    break
        return t

    def set_type(self, material):
        self.material = material

class Config:
    def __init__(self, file_name, load_defaults=True, save_defaults=False, separator="="):
        self.file_name = file_name
        self.load_defaults = load_defaults
        self.save_defaults = save_defaults
        self.separator = separator

    @staticmethod
    def new(file_path, load_defaults=True, save_defaults=False, separator="="):
        return Config(file_path, load_defaults, save_defaults, separator)

class EntityData:
    pass

p_any = re.compile("(.*)")
```

This Python code is a direct translation of the Java code provided. It uses classes and methods to represent the same concepts as in the original Java code.