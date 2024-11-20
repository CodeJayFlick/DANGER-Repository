class EvtEntityBlockChange:
    def __init__(self):
        self.monster_egg = "any spawn egg"

    patterns = ["enderman place", "enderman pickup", "sheep eat", "silverfish enter", "silverfish exit", "falling block land"]

    class ChangeEvent:
        values = [patterns[0], patterns[1], patterns[2], patterns[3], patterns[4], patterns[5]]

        def __init__(self, pattern):
            self.pattern = pattern

        @staticmethod
        def register_event():
            for i in range(len(patterns)):
                if patterns[i].startswith("enderman"):
                    Skript.register_event(f"{patterns[i]}", EvtEntityBlockChange, EntityChangeEvent, ChangeEvent.values[i])
                elif patterns[i].startswith("sheep"):
                    Skript.register_event(f"on {patterns[i]}:", EvtEntityBlockEvent)
                elif patterns[i].startswith("silverfish"):
                    Skript.register_event(f"on {patterns[i]}:", EvtEntityBlockEvent)
                else:
                    Skript.register_event(f"on {patterns[i]} land", EvtEntityBlockEvent)

        @staticmethod
        def description():
            return f"CALLED WHEN AN ENDMAN PLACES OR PICKS UP A BLOCK, A SHEEP EATS GRASS, " \
                   f"A SILVERFISH BOOPS INTO/OUT OF A BLOCK OR A FALLING BLOCK LAND AND TURNS INTO A BLOCK RESPECTIVELY."

        @staticmethod
        def examples():
            return ["on sheep eat:", "kill entity", "broadcast \"A sheep stole some grass!\"", "on falling block land:", 
                    "if event-entity is a falling dirt: cancel event"]

        @staticmethod
        def since():
            return "<i>unknown</i>, 2.5.2 (falling block)"

    register_event = ChangeEvent.register_event

    description = ChangeEvent.description

    examples = ChangeEvent.examples

    since = ChangeEvent.since


class EntityChangeEvent:
    pass


def init(self, args, matched_pattern):
    self.event = EvtEntityBlockChange.ChangeEvent.values[matched_pattern]
    return True


def check(self, e):
    if not isinstance(e, EntityChangeEvent):
        return False
    return EvtEntityBlockChange.ChangeEvent.values.index(self.event.pattern) == 0 and isinstance(e.get_entity(), Enderman)


@staticmethod
def main():
    pass

if __name__ == "__main__":
    main()
