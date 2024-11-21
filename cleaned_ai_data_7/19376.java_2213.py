class EffScriptFile:
    def __init__(self):
        self.mark = None
        self.file_name = None

    @staticmethod
    def register_effect():
        Skript.register_effect(EffScriptFile, "(1¦enable|1¦load|2¦reload|3¦disable|3¦unload) s(cript)?  file %string%")

    ENABLE = 1
    RELOAD = 2
    DISABLE = 3

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.mark = parse_result['mark']
        self.file_name = exprs[0]
        return True

    def __str__(self, e=None, debug=False):
        if self.mark == EffScriptFile.ENABLE:
            action = "enable"
        elif self.mark == EffScriptFile.RELOAD:
            action = "reload"
        elif self.mark == EffScriptFile.DISABLE:
            action = "disable"
        else:
            return ""

        file_name_str = "" if not self.file_name else str(self.file_name)
        return f"{action} script file {file_name_str}"

    def execute(self, e):
        name = self.file_name.get_single(e) if self.file_name else ""
        file = SkriptCommand.get_script_from_name(name or "")
        if file is None:
            return

        if self.mark == EffScriptFile.ENABLE and not file.name.startswith("-"):
            return
        elif self.mark == EffScriptFile.DISABLE and file.name.startswith("-"):
            return

        try:
            new_file = FileUtils.move(file, File(file.parent / (file.name[1:])), False)
        except IOException as ex:
            Skript.exception(ex, f"Error while {action} script file: {name}")
            return

        if self.mark == EffScriptFile.ENABLE and file.name.startswith("-"):
            config = ScriptLoader.load_structure(new_file)
            if config is not None:
                ScriptLoader.load_scripts([config], OpenCloseable.EMPTY)

        elif self.mark == EffScriptFile.RELOAD:
            ScriptLoader.reload_script(file, OpenCloseable.EMPTY)

        elif self.mark == EffScriptFile.DISABLE and file.name.startswith("-"):
            try:
                new_file = FileUtils.move(new_file, File(file.parent / ("-" + file.name)), False)
            except IOException as ex:
                Skript.exception(ex, f"Error while {action} script file: {name}")
        else:
            assert False
