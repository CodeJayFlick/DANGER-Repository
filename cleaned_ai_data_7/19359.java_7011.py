class MakeFly:
    def __init__(self):
        self.players = None
        self.flying = False

    @staticmethod
    def register_effect():
        if hasattr(Player, 'set_flying'):
            Skript.register_effect(MakeFly, "force %players% to [(start|stop)] fly[ing]",
                                   "make %players% (start|stop) flying",
                                   "make %players% fly")

    @staticmethod
    def init(exprs):
        self.players = exprs[0]
        self.flying = not parse_result.mark == 1

    def execute(self, e):
        for player in players.get_array(e):
            player.set_allow_flight(flying)
            player.set_flying(flying)

    def __str__(self, e, debug=False):
        return "make {} {}".format(players.__str__(e, debug), flying and ' start' or ' stop') + 'flying'
