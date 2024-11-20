class PotionDataUtils:
    FIRE_RESISTANCE = (PotionType.FIRE_RESISTANCE, False, False, 3600, 0)
    FIRE_RESISTANCE_LONG = (PotionType.FIRE_RESISTANCE, True, False, 9600, 0)
    HARMING = (PotionType.INSTANT_DAMAGE, False, False, 1, 0)
    HARMING_STRONG = (PotionType.INSTANT_DAMAGE, False, True, 1, 1)
    HEALING = (PotionType.INSTANT_HEAL, False, False, 1, 0)
    HEALING_STRONG = (PotionType.INSTANT_HEAL, False, True, 1, 1)
    INVISIBILITY = (PotionType.INVISIBLE, False, False, 3600, 0)
    INVISIBILITY_LONG = (PotionType.INVISIBLE, True, False, 9600, 0)
    LEAPING = (PotionType.JUMP, False, False, 3600, 0)
    LEAPING_LONG = (PotionType.JUMP, True, False, 9600, 0)
    LEAPING_STRONG = (PotionType.JUMP, False, True, 1800, 1)
    LUCK = (PotionType.LUCK, False, False, 6000, 0)
    NIGHT_VISION = (PotionType.NIGHT_VISION, False, False, 3600, 0)
    NIGHT_VISION_LONG = (PotionType.NIGHT_VISION, True, False, 9600, 0)
    POISON = (PotionType.POISON, False, False, 900, 0)
    POISON_LONG = (PotionType.POISON, True, False, 1800, 0)
    POISON_STRONG = (PotionType.POISON, False, True, 432, 1)
    REGENERATION = (PotionType.REGEN, False, False, 900, 0)
    REGENERATION_LONG = (PotionType.REGEN, True, False, 1800, 0)
    REGENERATION_STRONG = (PotionType.REGEN, False, True, 450, 1)
    SLOW_FALLING = ("SLOW FALLING", False, False, 1800, 0) 
    SLOW_FALLING_LONG = ("SLOW FALLING", True, False, 4800, 0)
    SLOWNESS = (PotionType.SLOWNESS, False, False, 1800, 0)
    SLOWNESS_LONG = (PotionType.SLOWNESS, True, False, 4800, 0)
    SLOWNESS_STRONG = (PotionType.SLOWNESS, False, True, 400, 3)
    SWIFTNESS = (PotionType.SPEED, False, False, 3600, 0)
    SWIFTNESS_LONG = (PotionType.SPEED, True, False, 9600, 0)
    SWIFTNESS_STRONG = (PotionType.SPEED, False, True, 1800, 1)
    STRENGTH = (PotionType.STRENGTH, False, False, 3600, 0)
    STRENGTH_LONG = (PotionType.STRENGTH, True, False, 9600, 0)
    STRENGTH_STRONG = (PotionType.STRENGTH, False, True, 1800, 1)
    TURTLE_MASTER = ("TURTLE MASTER", False, False, 0, 0) 
    TURTLE_MASTER_LONG = ("TURTLE MASTER", True, False, 0, 0)
    TURTLE_MASTER_STRONG = ("TURTLE MASTER", False, True, 0, 0)
    WATER_BREATHING = (PotionType.WATER_BREATHING, False, False, 3600, 0)
    WATER_BREATHING_LONG = (PotionType.WATER_BREATHING, True, False, 9600, 0)

class PotionEffectUtils:
    @staticmethod
    def parse_by_effect_type(effect_type):
        if effect_type == "SLOW":
            return PotionEffectType.SLOW
        elif effect_type == "DAMAGE RESISTANCE":
            return PotionEffectType.DAMAGE_RESISTANCE

def get_potion_effects(potion_data):
    potion_effects = []
    for value in PotionDataUtils.__dict__.values():
        if isinstance(value, tuple) and len(value) > 0:
            name, extended, upgraded, duration, amplifier = value
            if name != "TURTLE MASTER":
                potion_type = get_potion_type(name)
                if potion_type is not None and (potion_data.type == potion_type or name in ["SLOW FALLING", "TURTLE MASTER"]):
                    if name in ["SLOW FALLING"]:
                        slow_amp = 5
                        resistance_amp = 3
                        duration = 800 if extended else 400
                        for _ in range(2):
                            potion_effects.append(PotionEffect(potion_type, duration, amplifier or slow_amp, False))
                    elif name == "TURTLE MASTER":
                        slow_amp = 5
                        resistance_amp = 3
                        duration = 800 if extended else 400
                        for _ in range(2):
                            potion_effects.append(PotionEffect(PotionEffectType.SLOW, duration, amplifier or slow_amp, False))
                            potion_effects.append(PotionEffect(PotionEffectType.DAMAGE_RESISTANCE, duration, amplifier or resistance_amp, False))

    return potion_effects

def get_special_turtle(data):
    potion_effects = []
    if data.name == "TURTLE MASTER":
        slow_amp = 5
        resistance_amp = 3
        duration = 800 if data.extended else 400
        for _ in range(2):
            potion_effects.append(PotionEffect(PotionEffectType.SLOW, duration, amplifier or slow_amp, False))
            potion_effects.append(PotionEffect(PotionEffectType.DAMAGE_RESISTANCE, duration, amplifier or resistance_amp, False))

    return potion_effects

class PotionData:
    def __init__(self):
        pass

def get_potion_type(name):
    if name == "FIRE RESISTANCE":
        return PotionType.FIRE_RESISTANCE
    elif name == "INSTANT DAMAGE":
        return PotionType.INSTANT_DAMAGE
    # Add more potion types here...

class PotionEffect:
    def __init__(self, effect_type, duration, amplifier, amplified):
        self.effect_type = effect_type
        self.duration = duration
        self.amplifier = amplifier
        self.amplified = amplified

PotionDataUtils()
