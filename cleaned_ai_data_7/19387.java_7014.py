class SwingHand:
    def __init__(self):
        self.SWINGING_IS_SUPPORTED = hasattr(LivingEntity, 'swingMainHand')
        Skript.register_effect(self.__class__, 
            "make %livingentities% swing [their] [main] hand", 
            "make %livingentities% swing [their] off[ ]hand")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not self.SWINGING_IS_SUPPORTED:
            Skript.error("The swing hand effect requires Minecraft 1.15.2 or newer")
            return False
        self.entities = exprs[0]
        self.is_main_hand = matched_pattern == 0
        return True

    def execute(self, e):
        if self.is_main_hand:
            for entity in self.entities.get_array(e):
                entity.swingMainHand()
        else:
            for entity in self.entities.get_array(e):
                entity.swingOffHand()

    def __str__(self, e=None, debug=False):
        return f"make {self.entities.__str__(e, debug)} swing their {'hand' if self.is_main_hand else 'off hand'}"
