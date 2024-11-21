class PassengerUtils:
    def __init__(self):
        pass

    @staticmethod
    def get_passenger(entity: 'Entity') -> list['Entity']:
        if hasattr(entity, 'getPassengers'):
            return list(entity.getPassengers())
        else:
            try:
                passenger = entity.__dict__['_passenger']
                return [passenger]
            except Exception as e:
                print(f"An error occurred while trying to get a passenger: {e}")

    @staticmethod
    def add_passenger(vehicle: 'Entity', passenger: 'Entity'):
        if vehicle is None or passenger is None:
            return

        try:
            if hasattr(vehicle, 'addPassenger'):
                vehicle.addPassenger(passenger)
            else:
                vehicle.__dict__['_passenger'] = passenger
        except Exception as e:
            print(f"An error occurred while trying to set a passenger: {e}")

    @staticmethod
    def remove_passenger(vehicle: 'Entity', passenger: 'Entity'):
        if vehicle is None or passenger is None:
            return

        try:
            if hasattr(vehicle, 'removePassenger'):
                vehicle.removePassenger(passenger)
            else:
                vehicle.__dict__['_passenger'] = None
        except Exception as e:
            print(f"An error occurred while trying to remove a passenger: {e}")

    @staticmethod
    def has_multiple_passenger() -> bool:
        return hasattr(Entity, 'getPassengers')
