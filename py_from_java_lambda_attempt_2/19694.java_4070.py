Here is a translation of the Java code into equivalent Python:

```Python
class TargetedBlock:
    def __init__(self):
        self.actual_targeted_block = None
        self.targeted_blocks = {}
        self.last_event = None
        self.blocks_valid_for_tick = 0

    @property
    def actual_targeted_block(self):
        return self._actual_targeted_block

    @actual_targeted_block.setter
    def actual_targeted_block(self, value):
        self._actual_targeted_block = value

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parser: dict) -> bool:
        if len(exprs) > 0:
            self.set_expr(exprs[0])
        self.actual_targeted_block = matched_pattern >= 2
        return True

    def __str__(self):
        if not self.last_event:
            return "the targeted block" + ("s" if self.get_expr().is_single() else "") + " of " + str(self.get_expr())
        return f"{Classes.debug_message(self.all(self.last_event))}"

    @property
    def last(self) -> 'Event':
        return self._last

    @last.setter
    def last(self, value):
        if not isinstance(value, Event):
            raise TypeError("Last event must be an instance of Event")
        self._last = value

    def get_targeted_block(self, p: Player, e: 'Event') -> Block:
        if not p:
            return None
        time = Bukkit.get_worlds()[0].get_full_time()
        if self.last != e or time != self.blocks_valid_for_tick:
            self.targeted_blocks.clear()
            self.blocks_valid_for_tick = time
            self.last = e
        if not self.actual_targeted_block and time <= 0 and p in self.targeted_blocks:
            return self.targeted_blocks[p]
#         if isinstance(e, PlayerInteractEvent) and p == (e).get_player() and ((PlayerInteractEvent)e).get_action() in [Action.LEFT_CLICK_BLOCK, Action.RIGHT_CLICK_BLOCK]:
#             self.targeted_blocks[(e).get_player()] = (e).get_clicked_block()
#             return (e).get_clicked_block()
        try:
            b = p.get_target_block(None, SkriptConfig.max_target_block_distance.value())
            if not isinstance(b, Block):
                raise TypeError("Target block must be an instance of Block")
            self.targeted_blocks[p] = b
            return b
        except Exception as ex:
            print(f"An error occurred: {ex}")
            return None

    def get(self, e: 'Event', source: list) -> list:
        return [self.get_targeted_block(p, e) for p in source]

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        super().set_time(value)
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.