class CondIsMember:
    def __init__(self):
        self.players = None
        self.regions = None
        self.owner = False

    @staticmethod
    def register_condition():
        Skript.register_condition("%offlineplayers% (is|are) (0¦[a] member|1¦[(the|an)] owner) of [[the] region] %regions%",
                                 "%offlineplayers% (is|are)(n' t| not) (0¦[a] member|1¦[(the|an)] owner) of [[the] region] %regions%")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.players = exprs[0]
        self.regions = exprs[1]
        self.owner = parse_result.mark == 1
        Skript.set_negated(matched_pattern == 1)
        return True

    def check(self, e):
        for p in self.players.check(e):
            if self.owner:
                if not any(r.is_owner(p) for r in self.regions.check(e)):
                    return False
            else:
                if not any(r.is_member(p) for r in self.regions.check(e)):
                    return False
        return True

    def __str__(self, e, debug):
        return f"{self.players} {('is' if self.players.single() else 'are')} {'not ' if Skript.negated() else ''}{'' if not self.owner else 'owner'}{'' if len(self.players) == 1 else 's'} of {self.regions}"
