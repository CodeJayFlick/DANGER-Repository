class Language:
    F_PLURAL = 1
    F_DEFINITE_ARTICLE = 2
    F_INDEFINITE_ARTICLE = 4
    
    NO_ARTICLE_MASK = ~(F_DEFINITE_ARTICLE | F_INDEFINITE_ARTICLE)
    
    name = "english"
    
    use_local = False
    english = {}
    localized = None

    def is_using_localized_language(self):
        return self.use_local

    def get_english_language(self):
        return dict(self.english)

    @staticmethod
    def get(key: str) -> str:
        if key.lower() in Language.english:
            return Language.english[key.lower()]
        else:
            return key.lower()

    @staticmethod
    def format(key, *args):
        value = Language.get(key)
        if value is None:
            return key
        try:
            return f"{value.format(*args)}"
        except Exception as e:
            print(f"Invalid format string at '{key}' in the {Language.name} language file: {str(e)}")
            return key

    @staticmethod
    def get_spaced(key):
        s = Language.get(key)
        if not s or s.strip() == "":
            return " "
        return f" {s} "

    @staticmethod
    def get_list(key) -> list:
        s = Language.get(key)
        if s is None:
            return [key.lower()]
        r = re.split(r"\s*,\s*", s)
        assert r, key
        return r

    @classmethod
    def load_default(cls, addon):
        if not addon.language_file_directory or not os.path.exists(addon.plugin.getResource(addon.language_file_directory + "/english.lang")):
            raise Exception(f"{addon} is missing the required english. lang file!")
        
        en = Config(addon.plugin.getResource(addon.language_file_directory + "/english.lang"), "english", False, False, ":").to_map(".")
        if not en or 'version' not in en:
            print(f"Missing version in {addon}'s default language file!")

        for key, value in en.items():
            Language.english[key] = value

    @classmethod
    def load(cls, name):
        name = name.lower()
        
        if name == "english":
            return True
        
        localized = {}
        exists = False
        
        for addon in Skript.get_addons():
            try:
                lang_file = Config(addon.plugin.getResource(addon.language_file_directory + "/" + name + ".lang"), name, False, False, ":").to_map(".")
                if not lang_file or 'version' not in lang_file:
                    print(f"Missing version in {addon}'s language file!")
                
                for key, value in lang_file.items():
                    localized[key] = value
            except Exception as e:
                print(f"Could not load the language file '{name}.lang': {str(e)}")
            
        if not exists and os.path.exists(addon.plugin.getResource(addon.language_file_directory + "/" + name + ".lang")):
            lang_file = Config(addon.plugin.getResource(addon.language_file_directory + "/" + name + ".lang"), name, False, False, ":").to_map(".")
            for key, value in lang_file.items():
                localized[key] = value
        
        if not exists and os.path.exists(os.path.join(addon.plugin.getDataFolder(), addon.language_file_directory + File.separator + name + ".lang")):
            try:
                with open(os.path.join(addon.plugin.getDataFolder(), addon.language_file_directory + File.separator + name + ".lang"), 'r') as f:
                    lang_file = json.load(f)
                    for key, value in lang_file.items():
                        localized[key] = value
            except Exception as e:
                print(f"Could not load the language file '{name}.lang': {str(e)}")
        
        if not exists and os.path.exists(os.path.join(addon.plugin.getDataFolder(), addon.language_file_directory + File.separator + name)):
            try:
                with open(os.path.join(addon.plugin.getDataFolder(), addon.language_file_directory + File.separator + name), 'r') as f:
                    lang_file = json.load(f)
                    for key, value in lang_file.items():
                        localized[key] = value
            except Exception as e:
                print(f"Could not load the language file '{name}': {str(e)}")
        
        if exists or os.path.exists(os.path.join(addon.plugin.getDataFolder(), addon.language_file_directory + File.separator + name)):
            Language.name = name
        
    @classmethod
    def validate_localized(cls):
        loc = cls.localized
        if not loc:
            return

        s = set(cls.english.keys())
        s -= set(loc.keys())
        remove_ignored(s)
        
        if len(s) > 0 and Skript.log_normal():
            print(f"The following messages have not been translated to {cls.name}: {', '.join(map(str, s))}")
        
        s = set(loc.keys())
        s -= set(cls.english.keys())
        remove_ignored(s)
        
        if len(s) > 0 and Skript.log_high():
            print(f"The localized language file has superfluous entries: {', '.join(map(str, s))}")

    @classmethod
    def add_listener(cls, l):
        cls.listeners.append(l)

    @staticmethod
    def set_use_local(b):
        if Language.use_local == b:
            return False
        
        if not Language.localized or not Language.english:
            return True
        
        Language.use_local = b
        for listener in Language.listeners:
            try:
                listener.on_language_change()
            except Exception as e:
                print(f"Error while changing the language {'' if b else 'from english to'}{Language.name}, Listener: {l}")
        
        return not b

    @staticmethod
    def is_using_local():
        return Language.use_local


class Config(dict):
    def __init__(self, file_like_object, name, use_section_names, ignore_empty_sections, section_separator):
        super().__init__()
        self.load(file_like_object, name, use_section_names, ignore_empty_sections, section_separator)

    @classmethod
    def load(cls, file_like_object, name, use_section_names, ignore_empty_sections, section_separator):
        for line in file_like_object:
            if not line.strip():
                continue
            
            parts = line.split(section_separator)
            
            key = None
            value = ""
            
            if len(parts) > 1 and use_section_names:
                key = parts[0].strip()
                
                if ignore_empty_sections and not key:
                    continue
                
                for part in parts[1:]:
                    if part.strip():
                        value += f"{part}{section_separator}"
            else:
                key, *value_parts = line.split(section_separator)
                value = section_separator.join(value_parts).strip()
            
            if use_section_names and key:
                cls[key] = value
            elif not key or ignore_empty_sections:
                continue
            
            super().__init__({key: value})
