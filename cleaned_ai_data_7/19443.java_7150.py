class EvtBlockLegacy:
    def __init__(self):
        self.types = None
        self.mine = False

    @staticmethod
    def register_events():
        if not Skript.is_running_minecraft(1, 13):
            Skript.register_event("Break / Mine", EvtBlockLegacy, [BlockBreakEvent, PlayerBucketFillEvent, HangingBreakEvent], "[block] (break[ing]|1¦min(e|ing)) [[of] %itemtypes%]")
                .description("Called when a block is broken by a player. If you use 'on mine', only events where the broken block dropped something will call the trigger.")
                .examples(["on mine:", "on break of stone:", "on mine of any ore:"])
                .since("1.0 (break), <i>unknown</i> (mine)")
            Skript.register_event("Burn", EvtBlockLegacy, [BlockBurnEvent], "[block] burn[ing] [[of] %itemtypes%]")
                .description("Called when a block is destroyed by fire.")
                .examples(["on burn:", "on burn of wood, fences, or chests:"])
                .since("1.0")
            Skript.register_event("Place", EvtBlockLegacy, [BlockPlaceEvent, PlayerBucketEmptyEvent, HangingPlaceEvent], "[block] (plac(e|ing)|build[ing]) [[of] %itemtypes%]")
                .description("Called when a player places a block.")
                .examples(["on place:", "on place of a furnace, workbench or chest:"])
                .since("1.0")
            Skript.register_event("Fade", EvtBlockLegacy, [BlockFadeEvent], "[block] fad(e|ing) [[of] %itemtypes%]")
                .description("Called when a block 'fades away', e.g. ice or snow melts.")
                .examples(["on fade of snow or ice:"])
                .since("1.0")
            Skript.register_event("Form", EvtBlockLegacy, [BlockFormEvent], "[block] form[ing] [[of] %itemtypes%]")
                .description("Called when a block is created, but not by a player, e.g. snow forms due to snowfall, water freezes in cold biomes.")
                .examples(["on form of snow:", "on form of a mushroom:"])
                .since("1.0")

    def init(self, args, matched_pattern, parser):
        self.types = Literal(args[0])
        self.mine = parser.mark == 1
        return True

    @staticmethod
    def check(event):
        if event and isinstance(event, BlockBreakEvent) and self.mine:
            if not ((BlockBreakEvent)event).get_block().get_drops((BlockBreakEvent)event).player.get_item_in_hand()).isEmpty():
                return False
        if self.types is None:
            return True

        item = None
        if isinstance(event, BlockFormEvent):
            item = ItemType(((BlockFormEvent) event).new_state)
        elif isinstance(event, (BlockEvent, PlayerBucketFillEvent)):
            item = ItemType(((event) if not isinstance(event, PlayerBucketEvent) else ((PlayerBucketEvent) event)).block_clicked.get_relative(((PlayerBucketEvent) event).block_face))
        elif isinstance(event, PlayerBucketEmptyEvent):
            item = ItemType(((PlayerBucketEmptyEvent) event).item_stack)
        # ... rest of the code
