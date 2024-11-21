class PlayerSkull:
    def __init__(self):
        self.player_skull = "player skull"
        self.new_skull_owner = Skript.method_exists(SkullMeta, "setOwningPlayer", OfflinePlayer)
        
    @property
    def player_skull(self):
        return self._player_skull
    
    @player_skull.setter
    def player_skull(self, value):
        self._player_skull = value

    @property
    def new_skull_owner(self):
        return self._new_skull_owner
    
    @new_skull_owner.setter
    def new_skull_owner(self, value):
        self._new_skull_owner = value

class ExprSkull:
    def __init__(self):
        pass

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        return super().init(exprs, matched_pattern, is_delayed, parse_result)

    @property
    def skull(self):
        if self.new_skull_owner:
            meta = SkullMeta()
            meta.setOwningPlayer(OfflinePlayer)
        else:
            meta = SkullMeta()
            meta.setOwner("offlineplayers")
        return ItemType(meta=meta)

    def get_return_type(self):
        return "ItemType"

    def get_property_name(self):
        return "skull"
