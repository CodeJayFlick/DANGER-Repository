class EffHidePlayerFromServerList:
    def __init__(self):
        self.players = None

    @property
    def players(self):
        return self._players

    @players.setter
    def players(self, value):
        if not isinstance(value, list) or not all(isinstance(player, dict) and 'player' in player for player in value):
            raise ValueError("Players must be a list of dictionaries with 'player' key")
        self._players = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if isinstance(exprs[0], list):
            players = [Player(player['player']) for player in exprs[0]]
        else:
            raise ValueError("Players must be a list of dictionaries with 'player' key")
        
        return True

    def execute(self, e):
        it = ((ServerListPingEvent) e).iterator()
        Iterators.remove_all(it, self.players)

    def __str__(self, e=None, debug=False):
        if not isinstance(e, ServerListPingEvent):
            raise ValueError("This method can only be called with a ServerListPingEvent")
        
        return f"hide {self.players} from the server list"

class Player:
    def __init__(self, player_name):
        self.player = player_name

# Registering effect
def register_effect():
    Skript.register_effect(EffHidePlayerFromServerList)

register_effect()
