class SecWhile:
    def __init__(self):
        self.condition = None
        self.actual_next = None
        self.do_while = False
        self.ran_do_while = False

    @staticmethod
    def register_section():
        Skript.register_section("[(1¦do)] while <.+>", SecWhile)

    def init(self, exprs, matched_pattern, is_delayed, parse_result, section_node, trigger_items):
        if len(exprs) != 0:
            self.condition = Condition.parse(exprs[0], "Can't understand this condition: " + str(exprs))
        else:
            return False
        self.do_while = (parse_result.mark == 1)
        load_optional_code(section_node)

    def walk(self, e):
        if not self.ran_do_while or self.condition.check(e):
            self.ran_do_while = True
            return self.walk(e, True)
        else:
            self.reset()
            debug(e, False)
            return self.actual_next

    def set_next(self, next_item):
        self.actual_next = next_item
        return self

    @property
    def actual_next(self):
        return self.actual_next

    def __str__(self, e=None, debug=False):
        if self.do_while:
            return "do while " + str(self.condition)
        else:
            return "while " + str(self.condition)

    def reset(self):
        self.ran_do_while = False
