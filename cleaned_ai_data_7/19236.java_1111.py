class HasScoreboardTag:
    def __init__(self):
        self.entities = None
        self.tags = None

    @staticmethod
    def register():
        if Skript.is_running_minecraft(1, 11):
            PropertyCondition.register(HasScoreboardTag, "HAVE", "[the] scoreboard tag[s] %strings%", "entities")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.entities = exprs[0]
        self.tags = exprs[1]
        if matched_pattern == 1:
            self.set_negated()
        return True

    def check(self, e):
        tags_list = list(map(str, self.tags.get_array(e)))
        for entity in self.entities.check(e):
            if not set(tags_list).issubset(set(entity.scoreboard_tags)):
                return False
        return not self.is_negated()

    def __str__(self, e=None, debug=False):
        return PropertyCondition.__str__(self, "HAVE", e, debug, self.entities, f"the scoreboard {'' if len(self.tags) == 1 else 's'} tag{'' if len(self.tags) == 1 else 's'}") + str(self.tags)

# Note: This is a Python translation of the given Java code. It does not include any specific Minecraft or Skript-related functionality, as that would require additional libraries and setup.
