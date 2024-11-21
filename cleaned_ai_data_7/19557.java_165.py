class ExperienceSpawnEvent:
    def __init__(self):
        self.spawned_xp = 0

class BlockBreakEvent:
    def __init__(self):
        self.exp_to_drop = 0

class ExprExperience:
    def __init__(self, skript=None):
        if not hasattr(self, 'skript'):
            self.skript = skript
        else:
            self.skript = getattr(self, 'skript')

    @staticmethod
    def register_expression():
        pass

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not (self.skript.is_current_event(ExperienceSpawnEvent) or self.skript.is_current_event(BlockBreakEvent)):
            print("The experience expression can only be used in experience spawn and block break events")
            return False
        return True

    def get(self, e):
        if isinstance(e, ExperienceSpawnEvent):
            return [Experience(((ExperienceSpawnEvent)e).get_spawned_xp())]
        elif isinstance(e, BlockBreakEvent):
            return [Experience(((BlockBreakEvent)e).get_exp_to_drop())]
        else:
            return []

class Experience:
    def __init__(self, xp=0):
        self.xp = xp

    @property
    def get_xp(self):
        return self.xp

    @get_xp.setter
    def set_xp(self, value):
        self.xp = value

def main():
    pass

if __name__ == "__main__":
    main()
