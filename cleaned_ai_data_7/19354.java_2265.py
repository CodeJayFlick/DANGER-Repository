class KillEffect:
    def __init__(self):
        self.entities = None

    @staticmethod
    def register_effect():
        Skript.register_effect(KillEffect)

    DAMAGE_AMOUNT = int('1' * 10)  # equivalent to Integer.MAX_VALUE in Java

    def init(self, exprs, matched_pattern, is_delayed, parser):
        if len(exprs) > 0:
            self.entities = exprs[0]
        return True

    def execute(self, e):
        for entity in self.entities.get_array(e):
            if isinstance(entity, EnderDragonPart):
                entity = entity.parent
            if hasattr(entity, 'get_max_health'):
                health_utils.damage(entity, entity.get_max_health() * 100)
            elif isinstance(entity, Player) and entity.game_mode == GameMode.CREATIVE:
                entity.set_game_mode(GameMode.SURVIVAL)
                health_utils.damage(entity, entity.get_max_health() * 100)
                entity.set_game_mode(GameMode.CREATIVE)

        if not hasattr(entity, 'remove') or isinstance(entity, Player):
            continue
        else:
            entity.remove()

    def __str__(self, e=None, debug=False):
        return f"kill {self.entities}"
