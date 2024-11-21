import logging

class Blacksmith:
    def __init__(self):
        pass

    @staticmethod
    def manufacture_weapon(weapon_type: str) -> dict:
        if weapon_type == "SPEAR":
            return {"type": "spear", "material": "wood"}
        elif weapon_type == "AXE":
            return {"type": "axe", "material": "stone"}
        else:
            raise ValueError("Invalid weapon type")

class OrcBlacksmith(Blacksmith):
    pass

class ElfBlacksmith(Blacksmith):
    pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    blacksmiths = [OrcBlacksmith(), ElfBlacksmith()]

    for blacksmith in blacksmiths:
        weapon_types = ["SPEAR", "AXE"]
        for weapon_type in weapon_types:
            try:
                weapon = Blacksmith.manufacture_weapon(weapon_type)
                logger.info(f"{blacksmith.__class__.__name__} manufactured {weapon}")
            except ValueError as e:
                logger.error(e)

