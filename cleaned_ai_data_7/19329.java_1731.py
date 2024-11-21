class CancelEvent:
    def __init__(self):
        self.cancel = None

    @property
    def cancel(self):
        return self._cancel

    @cancel.setter
    def cancel(self, value):
        self._cancel = value

    def init(self, vars=None, matched_pattern=0, is_delayed=False, parser=None):
        if is_delayed:
            print("Can't cancel an event anymore after it has already passed")
            return False
        self.cancel = matched_pattern == 0
        events = parser.get_current_events()
        if not events:
            return False
        for e in events:
            if isinstance(e, (Cancellable, BlockCanBuildEvent)):
                return True
        if parser.is_current_event(PlayerLoginEvent):
            print("A connect event cannot be cancelled, but the player may be kicked ('kick player by reason of \"...\"')")
        else:
            print(f"{parser.get_current_event_name()} event cannot be cancelled")
        return False

    def execute(self, e=None):
        if isinstance(e, Cancellable):
            e.set_cancelled(self.cancel)
        elif isinstance(e, PlayerInteractEvent):
            EvtClick.interact_tracker.event_modified((Cancellable) e)
            (e).set_use_item_in_hand(self.cancel and Result.DENY or Result.DEFAULT)
            (e).set_use_interacted_block(self.cancel and Result.DENY or Result.DEFAULT)
        elif isinstance(e, BlockCanBuildEvent):
            (e).set_buildable(not self.cancel)
        elif isinstance(e, PlayerDropItemEvent):
            PlayerUtils.update_inventory((e).get_player())

    def __str__(self, e=None, debug=False):
        return f"{'un' if not self.cancel else ''}cancel event"
