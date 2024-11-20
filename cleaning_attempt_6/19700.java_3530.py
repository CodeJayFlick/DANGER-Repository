class ExprTimes:
    def __init__(self):
        self.end = None

    @staticmethod
    def register_expression():
        Skript.register_expression(ExprTimes(), Long, "SIMPLE", ["%number% time[s]", "once", "twice"])

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result):
        self.end = exprs[0] if matched_pattern == 0 else SimpleLiteral(matched_pattern, False)

        if isinstance(self.end, Literal):
            amount = self.end.get_single().value
            if amount == 0 and Skript.is_in_loop():
                Skript.warning("Looping zero times makes the code inside of the loop useless")
            elif amount == 1 and Skript.is_in_loop():
                Skript.warning("Since you're looping exactly one time, you could simply remove the loop instead")
            elif amount < 0:
                if Skript.is_in_loop():
                    Skript.error("Looping a negative amount of times is impossible")
                else:
                    Skript.error("The times expression only supports positive numbers")

    def is_in_loop(self):
        node = Skript.get_node()
        return node and node.key.startswith("loop ")

    @staticmethod
    def get(node: Node, e) -> list or None:
        if not isinstance(e, Event):
            raise ValueError("Event expected")
        iter_ = iterator(e)
        return [i for i in iter_] if iter_ else []

    @staticmethod
    def iterator(e: Event) -> Iterator[int]:
        end = Skript.get_node().get_single(e).value
        return range(1, int(end) + 1)

    def is_single(self):
        return False

    def get_return_type(self):
        return Long

    def __str__(self, e=None, debug=False):
        if not isinstance(e, Event):
            raise ValueError("Event expected")
        return str(self.end) + " times"
