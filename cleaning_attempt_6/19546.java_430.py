class EnchantmentOfferExpression:
    def __init__(self):
        self.all = None
        self.expr_offer_number = None

    @staticmethod
    def register_expression():
        if 'org.bukkit.enchantments.EnchantmentOffer' in globals():
            from skript.lang.expression import ExpressionType, SimpleExpression
            from org.bukkit.event.enchantment import PrepareItemEnchantEvent
            Skript.register_expression(ExprEnchantmentOfferExpression, EnchantmentOffer, ExpressionType.SIMPLE,
                                       "[all [of]] [the] enchant[ment] offers",
                                       "enchant[ment] offer[s] %numbers%",
                                       "[the] %number%(st|nd|rd|th) enchant[ment] offer")

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result):
        if not self.get_parser().is_current_event(PrepareItemEnchantEvent):
            Skript.error("Enchantment offers are only usable in enchant prepare events", ErrorQuality.SEMANTIC_ERROR)
            return False
        if matched_pattern == 0:
            self.all = True
        else:
            self.expr_offer_number = exprs[0]
            self.all = False
        return True

    def get(self, event):
        if self.all:
            return [(PrepareItemEnchantEvent(event)).get_offers()]
        if not self.expr_offer_number:
            return [None]
        if self.expr_offer_number.is_single():
            offer_number = self.expr_offer_number.get_single(event)
            if offer_number is None:
                return [None]
            offer = int(offer_number) - 1
            if offer < 0 or offer > (PrepareItemEnchantEvent(event)).get_offers().length - 1:
                return [None]
            return [(PrepareItemEnchantEvent(event)).get_offers()[int(offer)]]

        offers = []
        for n in self.expr_offer_number.get_array(event):
            i = int(n) - 1
            if i >= 0 and i <= (PrepareItemEnchantEvent(event)).get_offers().length:
                offers.append((PrepareItemEnchantEvent(event)).get_offers()[int(i)])
        return [offer for offer in offers]

    def accept_change(self, mode):
        if mode == ChangeMode.SET or mode == ChangeMode.DELETE:
            return [EnchantmentType]
        return None

    def change(self, event: Event, delta: list | tuple, mode: ChangeMode):
        if not delta and mode != ChangeMode.DELETE:
            return
        et = EnchantmentType(delta[0]) if mode != ChangeMode.DELETE else None
        if isinstance(event, PrepareItemEnchantEvent):
            e = PrepareItemEnchantEvent(event)
            match mode:
                case ChangeMode.SET:
                    for i in range(3):
                        eo = e.get_offers()[i]
                        if eo is None:
                            eo = EnchantmentOffer(et.type(), et.level(), self.get_cost(i + 1, e.enchantment_bonus()))
                            e.set_offers([eo])
                        else:
                            eo.set_enchantment(et.type())
                            eo.set_level(et.level())
                    return
                case ChangeMode.DELETE:
                    if self.all:
                        for i in range(3):
                            e.set_offers([None] * 4)
                    else:
                        for n in self.expr_offer_number.get_array(event):
                            slot = int(n) - 1
                            eo = e.get_offers()[slot]
                            if eo is None:
                                eo = EnchantmentOffer(et.type(), et.level(), self.get_cost(slot + 1, e.enchantment_bonus()))
                                e.set_offers([eo])
                            else:
                                eo.set_enchantment(et.type())
                                eo.set_level(et.level())

    def get_cost(self, slot: int, bookshelves: int):
        base = (rand.randint(0, 7) + 1) + math.floor(bookshelves / 2) + rand.randint(0, bookshelves)
        match slot:
            case 1: return max(base // 3, 1)
            case 2: return (base * 2) // 3 + 1
            case 3: return max(base, bookshelves * 2)
            default: return 1

    def is_single(self):
        if not self.all and self.expr_offer_number.is_single():
            return True
        return False

    def get_return_type(self):
        return EnchantmentOffer

    def to_string(self, event=None, debug=False):
        match self.all:
            case True: return "the enchantment offers"
            case _ : return f"enchantment offer(s) {self.expr_offer_number.to_string(event, debug)}"
