class MiscellaneousUtils:
    @staticmethod
    def get_editor_component(editor):
        if editor.supports_custom_editor():
            return editor.get_custom_editor()
        elif isinstance(editor.value, bool):
            return PropertyBoolean(editor)
        elif editor.tags is not None:
            return PropertySelector(editor)
        elif editor.as_text is not None:
            return PropertyText(editor)

        clazz = type(editor)
        clazz_name = clazz.__name__
        if clazz_name.startswith("String"):
            # Most likely some kind of string editor with a null value.  Just use a string 
            # property and let the value be empty.
            return PropertyText(editor)

        raise ValueError(f"Ghidra does not know how to use PropertyEditor: {editor.__class__.__name__}")

    @staticmethod
    def collect_unique_instances(cls, map, key_func):
        for t in ClassSearcher.get_instances(cls):
            key = key_func(t)
            exists = map.get(key)
            if exists is not None:
                if isinstance(exists, type(t)):
                    continue
                Msg.error(LocationTrackingSpec.__class__, f"{cls.__name__} conflict over key: {key}")
            map[key] = t


# Assuming these classes exist in Python

class PropertyBoolean:
    def __init__(self, editor):
        pass

class PropertySelector:
    def __init__(self, editor):
        pass

class PropertyText:
    def __init__(self, editor):
        pass
