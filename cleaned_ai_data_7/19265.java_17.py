class CondIsSet:
    def __init__(self):
        self.expr = None

    @staticmethod
    def register_condition():
        Skript.register_condition(CondIsSet, "%~objects% (exist[s]|(is|are) set)", 
                                  "%~objects% (do[es](n' t| not) exist|(is|are)(n' t| not) set)")

    @staticmethod
    def init(exprs):
        self.expr = exprs[0]
        if len(exprs) == 1:
            return True

    def check(self, event):
        if isinstance(self.expr, list):
            for ex in self.expr:
                assert ex is not None
                result = self.check(ex, event)
                if (self.expr and not result or not self.expr and result):
                    return not result
            return self.expr
        else:
            all_values = self.expr.get_all(event)
            return not self.expr if self.is_negated() else len(all_values) != 0

    def __str__(self, event=None, debug=False):
        return f"{self.expr} {'isn\'t' if self.is_negated() else ' '}set"

class Skript:
    @staticmethod
    def register_condition(cls, pattern1, pattern2):
        pass

    @staticmethod
    def init():
        CondIsSet.register_condition()

if __name__ == "__main__":
    Skript.init()
