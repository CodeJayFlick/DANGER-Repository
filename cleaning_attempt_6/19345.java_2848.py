class FireworkLaunch:
    def __init__(self):
        self.effects = None
        self.locations = None
        self.lifetime = None

    @staticmethod
    def register_effect():
        pass  # equivalent to Skript.registerEffect in Java

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) != 3:
            return False
        self.effects = exprs[0]
        self.locations = exprs[1]
        self.lifetime = exprs[2]
        return True

    def execute(self, e):
        power = self.lifetime.get_single(e)
        if power is None:
            power = 1
        for location in self.locations.get_array(e):
            firework = location.world.spawn(location, Firework)
            meta = firework.firework_meta()
            meta.add_effects(self.effects.get_array(e))
            meta.set_power(int(power))
            firework.set_firework_meta(meta)

    def __str__(self, e=None, debug=False):
        return f"Launch firework(s) {self.effects} at location(s) {self.locations} timed {self.lifetime}"
