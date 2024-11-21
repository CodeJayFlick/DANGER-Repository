class PlayerListHeaderFooter:
    def __init__(self):
        self.mark = None

    @property
    def mark(self):
        return self._mark

    @mark.setter
    def mark(self, value):
        self._mark = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if Skript.method_exists(Player, 'set_player_list_header_footer', str, str):
            PropertyExpression.register(self.__class__, str, r'(player|tab)\ list\s?(header|footer)', 'players')
        self.mark = parse_result.mark
        return super().init(exprs, matched_pattern, is_delayed, parse_result)

    def convert(self, player):
        if self.mark == 0:
            return player.get_player_list_header()
        elif self.mark == 1:
            return player.get_player_list_footer()
        assert False
        return None

    def accept_change(self, mode):
        if mode in [Changer.ChangeMode.SET, Changer.ChangeMode.DELETE, Changer.ChangeMode.RESET]:
            return [str]
        return []

    def change(self, e, delta, mode):
        text = delta[0] if delta else ''
        for player in self.get_expr().get_array(e):
            if self.mark == 0:
                player.set_player_list_header(text)
            elif self.mark == 1:
                player.set_player_list_footer(text)

    def get_return_type(self):
        return str

    def get_property_name(self):
        return f'player list {("header" if self.mark == 0 else "footer")}'
