class ExprEnchantmentExpCosts:
    def __init__(self):
        self.expr_offer_number = None
        self.multiple = False

    @property
    def multiple(self):
        return self._multiple

    @multiple.setter
    def multiple(self, value):
        self._multiple = value

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result: dict) -> bool:
        if not isinstance(parse_result.get('event'), PrepareItemEnchantEvent):
            print("The enchantment exp level cost is only usable in an enchant prepare event.")
            return False
        if matched_pattern == 0:
            self.multiple = True
        else:
            self.expr_offer_number = exprs[0]
            self.multiple = False
        return True

    def get(self, event: PrepareItemEnchantEvent) -> list:
        if self.multiple:
            return [(cost,) for cost in event.get_exp_level_costs_offered()]
        offer_number = self.expr_offer_number.get_single(event)
        if offer_number is None:
            return []
        offer = int(offer_number)
        if 0 < offer <= len(event.get_exp_level_costs_offered()):
            return [event.get_exp_level_costs_offered()[offer - 1]]
        return []

    def accept_change(self, mode: ChangeMode) -> list or None:
        if mode in (ChangeMode.RESET, ChangeMode.DELETE, ChangeMode.REMOVE_ALL):
            return []
        return [Number, Experience]

    def change(self, event: PrepareItemEnchantEvent, delta: tuple, mode: ChangeMode) -> None:
        cost = int(delta[0])
        if 1 > cost:
            return
        offer = 0
        if self.expr_offer_number is not None:
            offer_number = self.expr_offer_number.get_single(event)
            if offer_number is not None:
                offer = int(offer_number) - 1
        for i in range(len(event.get_exp_level_costs_offered())):
            event.get_exp_level_costs_offered()[i] = cost

    def is_single(self) -> bool:
        return not self.multiple

    @property
    def return_type(self):
        return Long

    def __str__(self, e: PrepareItemEnchantEvent or None, debug: bool) -> str:
        if self.multiple:
            return "cost of enchantment offers"
        else:
            return f"cost of enchantment offer {self.expr_offer_number}"
