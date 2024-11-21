class VehicleEffect:
    def __init__(self):
        self.passengers = None
        self.vehicles = None

    @staticmethod
    def register_effect():
        Skript.register_effect(VehicleEffect, 
            "(make|let|force) %entities% [to] (ride|mount) [(in|on)] +%entities%/entitydatas%", 
            "(make|let|force) %entities% [to] (dismount|(dismount|leave) (from|of|) (any|the[ir]|his|her|) vehicle[s])", 
            "(eject|dismount) (any|the|) passenger[s] (of|from) +%entities%)")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if matched_pattern == 2:
            self.passengers = None
        else:
            self.passengers = exprs[0]
        
        if matched_pattern == 1:
            self.vehicles = None
        else:
            self.vehicles = exprs[-1]

        if not PassengerUtils.has_multiple_passenger() and \
           self.passengers is not None and self.vehicles is not None and \
           not self.passengers.is_single() and self.vehicles.is_single() and \
           isinstance(self.vehicles.get_return_type(), type(Entity)):
            Skript.warning("An entity can only have one passenger")

        return True

    def execute(self, e):
        vehicles = self.vehicles
        passengers = self.passengers
        
        if vehicles is None:
            assert passengers is not None
            for p in passengers.get_array(e):
                p.leave_vehicle()
            return
            
        if passengers is None:
            assert vehicles is not None
            for v in vehicles.get_array(e):
                (Entity(v)).eject()
            return

        vs = vehicles.get_array(e)
        ps = passengers.get_array(e)

        if len(vs) == 0:
            return
        
        if len(ps) == 0:
            return
        
        for v in vs:
            if isinstance(v, Entity):
                ((Entity)v).eject()
                for p in ps:
                    assert p is not None
                    p.leave_vehicle()
                    PassengerUtils.add_passenger((Entity)v, p)
            else:
                for p in ps:
                    assert p is not None
                    en = (v.spawn(p.location))
                    if en is None:
                        return
                    PassengerUtils.add_passenger(en, p)

    def __str__(self, e=None, debug=False):
        vehicles = self.vehicles
        passengers = self.passengers
        
        if vehicles is None:
            assert passengers is not None
            return "make {} dismount".format(passengers)
        
        if passengers is None:
            assert vehicles is not None
            return "eject passenger{} of {}".format("s" if len(vehicles) > 1 else "", vehicles)

        return "make {} ride {}".format(passengers, vehicles)
