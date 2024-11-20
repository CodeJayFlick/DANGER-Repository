class WhitelistExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Whitelist"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return """A server's whitelist.
This expression can be used to add/remove players to/from the whitelist,
to enable it and disable it (set whitelist to true / set whitelist to false),
and to empty it (reset whitelist)"""

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["set whitelist to false", "add all players to whitelist", "reset the whitelist"]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "2.5.2"

    @since.setter
    def since(self, value):
        self._since = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        return True

    def get(self, e=None):
        if not hasattr(self, '_whitelist'):
            self._whitelist = list(Bukkit.get_server().get_whitelisted_players())
        return self._whitelist

    def accept_change(self, mode):
        if mode in [ChangeMode.ADD, ChangeMode.REMOVE]:
            return [OfflinePlayer]
        elif mode in [ChangeMode.SET, ChangeMode.RESET]:
            return [bool]

    def change(self, e=None, delta=None, mode=ChangeMode.NORMAL):
        if mode == ChangeMode.SET:
            Bukkit.set_whitelist(delta[0])
        elif mode == ChangeMode.ADD:
            for p in delta:
                (OfflinePlayer(p)).set_whitelisted(True)
        elif mode == ChangeMode.REMOVE:
            for p in delta:
                (OfflinePlayer(p)).set_whitelisted(False)
        elif mode == ChangeMode.RESET:
            for p in Bukkit.get_server().get_whitelisted_players():
                p.set_whitelisted(False)

    def is_single(self):
        return False

    def get_return_type(self):
        return OfflinePlayer

    def __str__(self, e=None, debug=False):
        return "whitelist"
