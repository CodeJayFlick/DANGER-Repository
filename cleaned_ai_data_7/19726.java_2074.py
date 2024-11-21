import time
from typing import List, Tuple, Optional

class Entity:
    def __init__(self):
        pass

    def get_vehicle(self) -> 'Entity':
        return self

    def eject(self):
        pass

    def leave_vehicle(self):
        pass

    def set_passenger(self, passenger: 'Entity'):
        pass


def vehicle_enter_event(vehicle: 'Entity') -> Tuple[Optional['Event'], Optional[int]]:
    return None, 0


def vehicle_exit_event(vehicle: 'Entity') -> Tuple[Optional['Event'], Optional[int]]:
    return None, 0


class VehicleExpression:
    def __init__(self):
        pass

    @staticmethod
    def get_return_type() -> type:
        return Entity

    def convert(self, entity: 'Entity', event: Optional['Event'] = None) -> 'Entity':
        if isinstance(event, (VehicleEnterEvent, VehicleExitEvent)):
            return getattr(event, 'get_vehicle')()
        elif has_mount_events and isinstance(event, (EntityMountEvent, EntityDismountEvent)):
            return getattr(event, 'get_mount' if isinstance(event, EntityMountEvent) else 'get_dismounted')
        return entity.get_vehicle()

    def get(self, event: Optional['Event'], source: List[Optional['Entity']]) -> List[Tuple[Optional['Entity'], int]]:
        converter = Converter()
        result = []
        for p in source:
            if isinstance(event, (VehicleEnterEvent, VehicleExitEvent)):
                vehicle = self.convert(p, event)
                result.append((vehicle, 0))
            elif has_mount_events and isinstance(event, (EntityMountEvent, EntityDismountEvent)):
                vehicle = self.convert(p, event)
                result.append((vehicle, 0))
            else:
                result.append((p.get_vehicle(), 0))
        return result

    def change(self, mode: str):
        if mode == 'set':
            delta = [Entity()]
            super().change(delta)


class Converter:
    @staticmethod
    def convert(entity: Entity) -> Optional[Entity]:
        pass


has_mount_events = True
