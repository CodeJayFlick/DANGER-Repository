class EvtPressurePlate:
    def __init__(self):
        self.tripwire = None
    
    @staticmethod
    def register_event():
        Skript.register_event("Pressure Plate / Trip", EvtPressurePlate, PlayerInteractEvent,
                              "[step[ping] on] [a] [pressure] plate",
                              "(trip|[step[ping] on] [a] tripwire)")
    
    def init(self, args, matched_pattern, parser):
        self.tripwire = matched_pattern == 1
        return True
    
    def check(self, event):
        block = (event.get_player_interact_event()).get_clicked_block()
        if block is None:
            type_ = None
        else:
            type_ = block.get_type()
        
        action = (event.get_player_interact_event()).get_action()
        return isinstance(type_, str) and action == "PHYSICAL" and \
               ((self.tripwire and 
                 (type_ in ["TRIPWIRE", "TRIPWIRE_HOOK"] or type_.endswith("_HOOK")) or
                not self.tripwire and EvtPressurePlate.plate.is_type_of(type_))
    
    def __str__(self, event=None, debug=False):
        return f"trip{'ing' if self.tripwire else ''}"
