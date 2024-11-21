class CondItemInHand:
    def __init__(self):
        self.entities = None
        self.types = None
        self.off_tool = False

    @staticmethod
    def register_condition():
        if Skript.is_running_minecraft(1, 9):
            Skript.register_condition("[$living_entities$] have $itemtypes$ in [main] hand",
                                      "[$living_entities$] are holding $itemtypes$ [in main hand]",
                                      "[$living_entities$] have $itemtypes$ in off[-| ]hand",
                                      "[$living_entities$] are holding $itemtypes$ in off[-| ]hand",
                                      "[$living_entities$] do not have $itemtypes$ in [main] hand",
                                      "[$living_entities$] are not holding $itemtypes$ [in main hand]",
                                      "[$living_entities$] do not have $itemtypes$ in off[-| ]hand",
                                      "[$living_entities$] are not holding $itemtypes$ in off[-| ]hand")
        else:
            Skript.register_condition("[$living_entities$] have $itemtypes$ in hand",
                                      "[$living_entities$] are holding $itemtypes$ in hand",
                                      "[$living_entities$] do not have $itemtypes$",
                                      "[$living_entities$] are not holding $itemtypes$")

    def init(self, exprs, matched_pattern, is_delayed, parser):
        self.entities = exprs[0]
        self.types = exprs[1]
        if Skript.is_running_minecraft(1, 9):
            self.off_tool = (matched_pattern == 2 or matched_pattern == 3 or matched_pattern == 6 or matched_pattern == 7)
            self.set_negated(matched_pattern >= 4)
        else:
            self.off_tool = False
            self.set_negated(matched_pattern >= 2)
        return True

    def check(self, e):
        for en in entities.check(e):
            if types.check(e) and (off_tool or Skript.is_running_minecraft(1, 9)):
                equipment = en.get_equipment()
                if equipment is None:
                    return False
                if off_tool:
                    return type.is_type_of(equipment.get_item_in_off_hand())
                else:
                    return type.is_type_of(equipment.get_item_in_main_hand())

    def to_string(self, e, debug):
        return f"{entities.to_string(e, debug)} {('is' if entities.is_single() else 'are')} holding {types.to_string(e, debug)} {' in off-hand' if self.off_tool else ''}"
