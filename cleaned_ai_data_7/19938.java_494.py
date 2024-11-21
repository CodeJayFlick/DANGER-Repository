class PotionEffectUtils:
    HAS_SUSPICIOUS_META = Skript.class_exists("org.bukkit.inventory.meta.SuspiciousStewMeta")

    def __init__(self):
        pass

    types = {}
    names = []

    @staticmethod
    def parse_type(s):
        return types.get(s.lower())

    @staticmethod
    def parse_by_effect_type(t):
        for value in types.values():
            if t == value:
                return value
        return None

    @staticmethod
    def to_string(t, flags=0):
        return names[t.id]

    @staticmethod
    def to_string(potion_effect):
        builder = StringBuilder()
        if potion_effect.is_ambient:
            builder.append("ambient ")
        builder.append("potion effect of ")
        builder.append(PotionEffectUtils.to_string(potion_effect.type))
        
        builder.append(" of tier ").append(str(potion_effect.amplifier + 1))

        if not potion_effect.has_particles():
            builder.append(" without particles")
        builder.append(" for ").append(Timespan.from_ticks_i(potion_effect.duration))
        return builder.toString()

    @staticmethod
    def get_names():
        return names

    @staticmethod
    def guess_data(p):
        if len(p.effects) == 1:
            e = p.effects.next()
            t = PotionType.get_by_effect(e.type)
            assert t is not None
            d = new Potion(t).splash()
            return d.to_damage_value()

    @staticmethod
    def check_potion_type(name):
        switch name:
            case "uncraftable":
                return PotionType.UNCRAFTABLE
            case "empty":
                return PotionType.EMPTY
            # ... and so on

    @staticmethod
    def get_potion_name(effect, extended=False, strong=False):
        if effect is None: 
            return "bottle of water"
        
        s = ""
        if extended:
            s += "extended "
        elif strong:
            s += "strong "
        s += f"potion of {PotionEffectUtils.to_string(effect)}"
        return s

    @staticmethod
    def clear_all_effects(entity):
        entity.active_potion_effects.clear()
        for potion_effect in entity.active_potion_effects:
            entity.remove_potion_effect(potion_effect.type)

    @staticmethod
    def add_effects(entity, effects):
        for effect in effects:
            if isinstance(effect, PotionEffect):
                entity.add_potion_effect(effect)
            elif isinstance(effect, PotionEffectType):
                entity.add_potion_effect(PotionEffect(effect, 15 * 20, 0, False))

    @staticmethod
    def remove_effects(entity, effects):
        for effect in effects:
            if isinstance(effect, PotionEffect):
                type = effect.type
            elif isinstance(effect, PotionEffectType):
                type = effect
            else: 
                continue
            
            entity.remove_potion_effect(type)

    @staticmethod
    def clear_all_effects(item_type):
        meta = item_type.item_meta
        if isinstance(meta, PotionMeta): 
            meta.clear_custom_effects()
        elif HAS_SUSPICIOUS_META and isinstance(meta, SuspiciousStewMeta):
            meta.clear_custom_effects()

    @staticmethod
    def add_effects(item_type, effects):
        for effect in effects:
            if isinstance(effect, PotionEffect):
                item_type.item_meta.add_custom_effect(effect, False)
            elif isinstance(effect, PotionEffectType):
                item_type.item_meta.add_custom_effect(PotionEffect(effect, 15 * 20, 0, False), False)

    @staticmethod
    def remove_effects(item_type, effects):
        meta = item_type.item_meta
        
        for effect in effects:
            if isinstance(effect, PotionEffect):
                type = effect.type
            elif isinstance(effect, PotionEffectType):
                type = effect
            else: 
                continue
            
            if isinstance(meta, PotionMeta): 
                meta.remove_custom_effect(type)
            elif HAS_SUSPICIOUS_META and isinstance(meta, SuspiciousStewMeta):
                meta.remove_custom_effect(type)

    @staticmethod
    def get_effects(item_type):
        effects = []
        meta = item_type.item_meta
        
        if isinstance(meta, PotionMeta): 
            for effect in meta.get_custom_effects():
                effects.append(effect)
            base_potion_data = meta.base_potion_data()
            for potion_effect in PotionDataUtils.get_potion_effects(base_potion_data):
                effects.append(potion_effect)

        elif HAS_SUSPICIOUS_META and isinstance(meta, SuspiciousStewMeta): 
            effects.extend(meta.get_custom_effects())

        return effects
