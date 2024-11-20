class MendingRepairAmount:
    def __init__(self):
        pass

    @property
    def description(self):
        return ["The number of durability points an item is to be repaired in a mending event.",
                "Modifying the repair amount will affect how much experience is given to the player after mending."]

    @property
    def examples(self):
        return [{"on item mend:", 
                 "\tset the mending repair amount to 100"}]

    @property
    def since(self):
        return "2.5.1"

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not self.parser.is_current_event(PlayerItemMendEvent):
            Skript.error("The 'mending repair amount' is only usable in item mend events", ErrorQuality.SEMANTIC_ERROR)
            return False
        return True

    def get(self, event):
        return [(long((PlayerItemMendEvent)(event)).get_repair_amount())]

    @property
    def accept_change(self):
        return {ChangeMode.SET: [int],
                ChangeMode.ADD: [int],
                ChangeMode.REMOVE: [int],
                ChangeMode.RESET: None}

    def change(self, event, delta, mode):
        e = PlayerItemMendEvent(event)
        new_level = 0
        if delta:
            new_level = (Number(delta[0])).intValue()
        match mode:
            case ChangeMode.SET:
                pass
            case ChangeMode.ADD:
                new_level += e.get_repair_amount()
            case ChangeMode.REMOVE:
                new_level = e.get_repair_amount() - new_level
            case ChangeMode.RESET:
                repair_amount = (e.experience_orb().get_experience()) * 2
                item_damage = ItemUtils.get_damage(e.item())
                new_level = min(item_damage, repair_amount)
        e.set_repair_amount(new_level)

    @property
    def is_single(self):
        return True

    @property
    def get_return_type(self):
        return Long

    def __str__(self):
        return "the mending repair amount"
