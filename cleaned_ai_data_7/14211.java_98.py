class WeaponFactory:
    def __init__(self):
        self.map = {}

    @staticmethod
    def factory(consumer):
        wf = WeaponFactory()
        consumer(wf.put)
        return lambda name: wf.map.get(name)()

    def put(self, weapon_type: str, supplier: callable):
        self.map[weapon_type] = supplier

# Example usage:
def create_weapon(weapon_factory: 'WeaponFactory', weapon_type: str):
    return weapon_factory.create(weapon_type)

class Weapon:
    pass
