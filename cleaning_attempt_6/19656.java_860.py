class PotionEffects:
    def __init__(self):
        self.objects = None
    
    @property
    def objects(self):
        return self._objects
    
    @objects.setter
    def objects(self, value):
        self._objects = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) > 0:
            self.objects = exprs[0]
        return True

    def get(self, e):
        effects = []
        for obj in self.objects:
            if isinstance(obj, LivingEntity):
                effects.extend(obj.get_active_potion_effects())
            elif isinstance(obj, ItemType):
                effects.extend(PotionEffectUtils.get_effects(obj))
        return [PotionEffect(*effect) for effect in effects]

    def accept_change(self, mode):
        if mode in (ChangeMode.REMOVE, ChangeMode.ADD, ChangeMode.DELETE):
            return [PotionEffectType] + [PotionEffect]
        else:
            return None

    def change(self, e, delta, mode):
        for obj in self.objects:
            if isinstance(obj, LivingEntity):
                if mode == ChangeMode.DELETE:
                    PotionEffectUtils.clear_all_effects(obj)
                elif mode == ChangeMode.ADD and delta is not None:
                    PotionEffectUtils.add_effects(obj, [PotionEffect(*effect) for effect in delta])
                elif mode == ChangeMode.REMOVE and delta is not None:
                    PotionEffectUtils.remove_effects(obj, [PotionEffect(*effect) for effect in delta])

            elif isinstance(obj, ItemType):
                if mode == ChangeMode.DELETE:
                    PotionEffectUtils.clear_all_effects(obj)
                elif mode == ChangeMode.ADD and delta is not None:
                    PotionEffectUtils.add_effects(obj, [PotionEffect(*effect) for effect in delta])
                elif mode == ChangeMode.REMOVE and delta is not None:
                    PotionEffectUtils.remove_effects(obj, [PotionEffect(*effect) for effect in delta])

    def is_single(self):
        return False

    def get_return_type(self):
        return PotionEffect

    def __str__(self, e=None, debug=False):
        if self.objects is not None and len(self.objects) > 0:
            return f"active potion effects of {', '.join(map(str, self.objects))}"
        else:
            return "no objects"
