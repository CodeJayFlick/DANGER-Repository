class SendBlockChange:
    def __init__(self):
        self.BLOCK_DATA_SUPPORT = hasattr(bukkit, 'block_data')
        self.SUPPORTED = hasattr(bukkit, 'Player') and hasattr(bukkit.Player, 'send_block_change')

    @staticmethod
    def register_effect():
        if SendBlockChange.BLOCK_DATA_SUPPORT:
            Skript.register_effect("make %players% see %blocks% as %itemtype/blockdata")
        else:
            Skript.register_effect("make %players% see %blocks% as %itemtype")

    def init(self, exprs):
        if not self.SUPPORTED:
            print("The send block change effect is not supported on this version.")
            return False
        self.players = exprs[0]
        self.blocks = exprs[1]
        self.as = exprs[2]
        return True

    def execute(self, e):
        object = self.as.get_single(e)
        if isinstance(object, bukkit.Material):
            for player in self.players.get_array(e):
                for block in self.blocks.get_array(e):
                    object.send_block_change(player, block.location)
        elif SendBlockChange.BLOCK_DATA_SUPPORT and isinstance(object, bukkit.block_data.BlockData):
            for player in self.players.get_array(e):
                for block in self.blocks.get_array(e):
                    player.send_block_change(block.location, object)

    def __str__(self, e=None, debug=False):
        return f"make {self.players} see {self.blocks} as {self.as}"
