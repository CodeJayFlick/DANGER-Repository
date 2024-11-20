class EnchantItem:
    def __init__(self):
        self.register_expression()

    @staticmethod
    def register_expression():
        Skript().register_expression(EnchantItem(), ExpressionType.SIMPLE, "[the] enchanted item")

    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult) -> bool:
        if not self.get_parser().is_current_event((EnchantItemEvent, PrepareItemEnchantEvent)):
            Skript.error("The enchant item is only usable in an enchant prepare event or enchant event.", ErrorQuality.SEMANTIC_ERROR)
            return False
        return True

    def get(self, e: Event) -> list[ItemType]:
        if isinstance(e, PrepareItemEnchantEvent):
            return [new ItemType(((PrepareItemEnchantEvent)e).get_item())]
        else:
            return [new ItemType(((EnchantItemEvent)e).get_item())]

    @staticmethod
    def accept_change(mode: ChangeMode) -> list[Class]:
        if mode == ChangeMode.SET:
            return [ItemType]
        return []

    def change(self, event: Event, delta: tuple[object], mode: ChangeMode):
        if not delta:
            return
        item = ItemType(delta[0])
        match mode:
            case ChangeMode.SET:
                if isinstance(event, PrepareItemEnchantEvent):
                    e = (PrepareItemEnchantEvent)event
                    e.get_item().set_type(item.get_material())
                    e.get_item().set_item_meta(item.get_item_meta())
                    e.get_item().set_amount(item.get_amount())
                else:
                    e = (EnchantItemEvent)event
                    e.get_item().set_type(item.get_material())
                    e.get_item().set_item_meta(item.get_item_meta())
                    e.get_item().set_amount(item.get_amount())

    def is_single(self):
        return True

    @staticmethod
    def get_return_type():
        return ItemType

    def __str__(self, event: Event = None, debug: bool = False) -> str:
        if not event and not debug:
            return "enchanted item"
