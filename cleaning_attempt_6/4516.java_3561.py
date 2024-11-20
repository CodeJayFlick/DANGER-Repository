class ScriptInfo:
    DELIMITER = "."

    AT_AUTHOR = "@author"
    AT_CATEGORY = "@category"
    AT_KEYBINDING = "@keybinding"
    AT_MENUPATH = "@menupath"
    AT_TOOLBAR = "@toolbar"

    METADATA = [AT_AUTHOR, AT_CATEGORY, AT_KEYBINDING, AT_MENUPATH, AT_TOOLBAR]

    def __init__(self, provider: str, source_file: str):
        self.provider = provider
        self.source_file = source_file

        if not os.path.exists(source_file):
            raise Exception("Source file for script does not exist!")

    def init(self) -> None:
        self.description = ""
        self.author = None
        self.category = []
        self.key_binding = None
        self.menu_path = []
        self.toolbar = None
        self.toolbar_image = None
        self.import_package = None

    def refresh(self) -> None:
        self.toolbar_image = None

    @property
    def name(self):
        return os.path.basename(self.source_file)

    @property
    def source_file_name(self):
        return self.name

    def get_author(self) -> str:
        self.parse_header()
        return self.author

    def is_compile_errors(self) -> bool:
        return self.is_compile_errors_

    def set_compile_errors(self, b: bool) -> None:
        self.is_compile_errors_ = b

    @property
    def duplicate(self):
        return self.duplicate_

    def set_duplicate(self, b: bool) -> None:
        self.duplicate_ = b

    def get_description(self) -> str:
        self.parse_header()
        return self.description

    def parse_header(self) -> None:
        if not os.path.exists(self.source_file):
            return
        try:
            with open(self.source_file, 'r') as file:
                for line in file:
                    if line.startswith("#"):
                        continue
                    elif line.strip() == "":
                        continue
                    else:
                        self.parse_metadata_line(line)
        except Exception as e:
            print(f"Unexpected exception reading script: {self.name}, {e}")

    def parse_metadata_line(self, line: str) -> None:
        if line.startswith(AT_AUTHOR):
            self.author = get_tag_value(AT_AUTHOR, line)
        elif line.startswith(AT_CATEGORY):
            tag_value = get_tag_value(AT_CATEGORY, line)
            if tag_value is not None:
                self.category = split_string(tag_value, self.DELIMITER)
        elif line.startswith(AT_KEYBINDING):
            tag_value = get_tag_value(AT_KEYBINDING, line)
            if tag_value is not None:
                self.set_key_binding(tag_value)
        elif line.startswith(AT_MENUPATH):
            tag_value = get_tag_value(AT_MENUPATH, line)
            if tag_value is not None:
                tokenizer = StringTokenizer(tag_value, self.DELIMITER)
                for i in range(tokenizer.countTokens()):
                    token = tokenizer.nextToken()
                    if i == tokenizer.countTokens() - 1:
                        self.menu_path.append(token.upper())
                    else:
                        self.menu_path.append(token.lower())
        elif line.startswith(AT_TOOLBAR):
            self.toolbar = get_tag_value(AT_TOOLBAR, line)
        elif line.startswith(AT_IMPORTPACKAGE):
            self.import_package = get_tag_value(AT_IMPORTPACKAGE, line)

    def is_category(self, other_category: list) -> bool:
        if not os.path.exists(self.source_file):
            return True
        try:
            with open(self.source_file, 'r') as file:
                for line in file:
                    if line.startswith("#"):
                        continue
                    elif line.strip() == "":
                        continue
                    else:
                        self.parse_metadata_line(line)
        except Exception as e:
            print(f"Unexpected exception reading script: {self.name}, {e}")
        return all(i.lower() == j.lower() for i, j in zip(self.category, other_category))

    def get_menu_path(self) -> list:
        if not os.path.exists(self.source_file):
            return []
        try:
            with open(self.source_file, 'r') as file:
                for line in file:
                    if line.startswith("#"):
                        continue
                    elif line.strip() == "":
                        continue
                    else:
                        self.parse_metadata_line(line)
        except Exception as e:
            print(f"Unexpected exception reading script: {self.name}, {e}")
        return self.menu_path

    def get_key_binding(self) -> str:
        if not os.path.exists(self.source_file):
            return ""
        try:
            with open(self.source_file, 'r') as file:
                for line in file:
                    if line.startswith("#"):
                        continue
                    elif line.strip() == "":
                        continue
                    else:
                        self.parse_metadata_line(line)
        except Exception as e:
            print(f"Unexpected exception reading script: {self.name}, {e}")
        return self.key_binding

    def get_import_package(self) -> str:
        if not os.path.exists(self.source_file):
            return ""
        try:
            with open(self.source_file, 'r') as file:
                for line in file:
                    if line.startswith("#"):
                        continue
                    elif line.strip() == "":
                        continue
                    else:
                        self.parse_metadata_line(line)
        except Exception as e:
            print(f"Unexpected exception reading script: {self.name}, {e}")
        return self.import_package

    def get_tooltip_text(self) -> str:
        if not os.path.exists(self.source_file):
            return ""
        try:
            with open(self.source_file, 'r') as file:
                for line in file:
                    if line.startswith("#"):
                        continue
                    elif line.strip() == "":
                        continue
                    else:
                        self.parse_metadata_line(line)
        except Exception as e:
            print(f"Unexpected exception reading script: {self.name}, {e}")
        return f"<h3>{os.path.basename(self.source_file)}</h3><br/>{self.description}<br/>{bold('Author:') + ' ' + str(self.author)}<br/>{bold('Category:') + ' ' + str(self.category)}<br/>{bold('Key Binding:') + ' ' + self.key_binding}<br/>{bold('Menu Path:') + ' ' + str(self.menu_path)}"

    def has_errors(self) -> bool:
        return self.is_compile_errors_ or self.duplicate_

    @property
    def error_message(self):
        if self.is_compile_errors():
            return "Error compiling script (see console)"
        elif self.duplicate():
            return "Script is a duplicate of another script"
        else:
            return None

def get_tag_value(tag: str, line: str) -> str:
    if not line.startswith(tag):
        return None
    return line[len(tag):].strip()

def split_string(string: str, delimiter: str) -> list:
    tokenizer = StringTokenizer(string, delimiter)
    result = []
    for i in range(tokenizer.countTokens()):
        token = tokenizer.nextToken()
        result.append(token.strip())
    return result

def bold(text: str) -> str:
    return f"<b>{text}</b>"

if __name__ == "__main__":
    provider = "java"
    source_file = "script.py"
    script_info = ScriptInfo(provider, source_file)
