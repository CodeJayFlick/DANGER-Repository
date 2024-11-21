class ShellUtils:
    class State(enum.Enum):
        NORMAL = 0
        NORMAL_ESCAPE = 1
        DQUOTE = 2
        DQUOTE_ESCAPE = 3
        SQUOTE = 4
        SQUOTE_ESCAPE = 5

    @staticmethod
    def parse_args(args: str) -> list[str]:
        args_list = []
        cur_arg = ""
        state = ShellUtils.State.NORMAL
        for c in args:
            if state == ShellUtils.State.NORMAL:
                if c == '\\':
                    state = ShellUtils.State.NORMAL_ESCAPE
                elif c == '"':
                    state = ShellUtils.State.DQUOTE
                elif c == "'":
                    state = ShellUtils.State.SQUOTE
                elif c.isspace():
                    args_list.append(cur_arg)
                    cur_arg = ""
                else:
                    cur_arg += c
            elif state == ShellUtils.State.NORMAL_ESCAPE:
                cur_arg += c
                state = ShellUtils.State.NORMAL
            elif state in [ShellUtils.State.DQUOTE, ShellUtils.State.SQUOTE]:
                if c == '\\':
                    state = state + "_ESCAPE"
                elif c == '"' and state == ShellUtils.State.DQUOTE:
                    state = ShellUtils.State.NORMAL
                elif c == "'" and state == ShellUtils.State.SQUOTE:
                    state = ShellUtils.State.NORMAL
                else:
                    cur_arg += c

        if cur_arg:
            args_list.append(cur_arg)

        return args_list

    @staticmethod
    def generate_line(args: list[str]) -> str:
        line = ""
        for arg in args[1:]:
            if ' ' in arg and '"' not in arg and "'" not in arg:
                line += " '" + arg + "' "
            elif ' ' in arg and '"' in arg and "'" not in arg:
                line += "\"" + arg.replace('"', '\\"') + "\""
            else:
                line += " \"" + arg + "\""

        return line.strip()
