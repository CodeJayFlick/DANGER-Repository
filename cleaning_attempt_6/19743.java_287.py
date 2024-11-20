class PrefixSuffix:
    def __init__(self):
        self.prefix = None

    @property
    def prefix(self):
        return self._prefix

    @prefix.setter
    def prefix(self, value):
        self._prefix = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if parse_result.mark == 1:
            self.prefix = True
        else:
            self.prefix = False
        return super().init(exprs, matched_pattern, is_delayed, parse_result)

    def convert(self, p):
        if self.prefix:
            return VaultHook.chat.get_player_prefix(p)
        else:
            return VaultHook.chat.get_player_suffix(p)

    @property
    def property_name(self):
        if self.prefix:
            return "prefix"
        else:
            return "suffix"

    @property
    def return_type(self):
        return str

    def accept_change(self, mode):
        if mode == ChangeMode.SET:
            return [str]
        return None

    def change(self, e, delta, mode):
        assert mode == ChangeMode.SET
        assert delta is not None
        for p in self.expr.get_array(e):
            if self.prefix:
                VaultHook.chat.set_player_prefix(p, str(delta[0]))
            else:
                VaultHook.chat.set_player_suffix(p, str(delta[0]))

class SkriptParser:
    def parse(self):
        pass

class Expression:
    def __init__(self):
        pass

    @property
    def expr(self):
        return self._expr

    @expr.setter
    def expr(self, value):
        self._expr = value

# Register the class with SkriptParser
SkriptParser().register(PrefixSuffix(), str, "[chat] (1¦prefix|2¦suffix)", "players")
