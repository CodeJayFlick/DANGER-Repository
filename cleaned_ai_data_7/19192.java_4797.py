class DefaultChangers:
    def __init__(self):
        pass

    entity_changer = Changer()
    player_changer = Changer()

    class EntityChanger(Changer):
        @staticmethod
        def accept_change(mode):
            if mode == ChangeMode.ADD:
                return [ItemType, Inventory, Experience]
            elif mode == ChangeMode.DELETE:
                return []
            elif mode in (ChangeMode.REMOVE, ChangeMode.REMOVE_ALL):
                return [PotionEffectType]
            else:
                assert False
                return None

        @staticmethod
        def change(entities, delta, mode):
            if delta is None:
                for e in entities:
                    if not isinstance(e, Player):
                        e.remove()
                return
            for e in entities:
                for d in delta:
                    if isinstance(d, PotionEffectType):
                        assert mode == ChangeMode.REMOVE or mode == ChangeMode.REMOVE_ALL
                        if not isinstance(e, LivingEntity):
                            continue
                        (LivingEntity)(e).remove_potion_effect((PotionEffectType)(d))
                    elif isinstance(d, Experience):
                        for p in entities:
                            if isinstance(p, Player):
                                p.give_exp(((Experience)(d)).get_xp())
                    else:
                        if isinstance(e, Player):
                            player = (Player)(e)
                            inventory = player.get_inventory()
                            if mode == ChangeMode.ADD:
                                for item_stack in delta[0]:
                                    if item_stack is not None:
                                        inventory.add_item(item_stack)
                            elif mode == ChangeMode.REMOVE or mode == ChangeMode.REMOVE_ALL:
                                if isinstance(d, Inventory):
                                    for i in d:
                                        if i is not None:
                                            inventory.remove_item(i)

    class PlayerChanger(Changer):
        @staticmethod
        def accept_change(mode):
            return entity_changer.accept_change(mode)

        @staticmethod
        def change(players, delta, mode):
            entity_changer.change(players, delta, mode)

    non_living_entity_changer = Changer()

    class NonLivingEntityChanger(Changer):
        @staticmethod
        def accept_change(mode):
            if mode == ChangeMode.DELETE:
                return []
            else:
                assert False
                return None

        @staticmethod
        def change(entities, delta, mode):
            for e in entities:
                if isinstance(e, Player):
                    continue
                e.remove()

    item_changer = Changer()
    inventory_changer = Changer()
    block_changer = Changer()


class ChangeMode:
    ADD = 1
    DELETE = 2
    REMOVE = 3
    REMOVE_ALL = 4
    SET = 5
    RESET = 6


class Changer:
    def __init__(self):
        pass

    @staticmethod
    def accept_change(mode):
        return None

    @staticmethod
    def change(entities, delta, mode):
        assert False
        return None


def main():
    default_changers = DefaultChangers()
