class ExprDurability:
    LEGACY_BLOCK = not Skript.is_running_minecraft(1, 13)

    @staticmethod
    def register():
        from ch.njol.skript import Skript
        from org.bukkit.block import Block

        if not hasattr(Skript, 'register_expression'):
            return None

        Skript.register_expression('((data|damage)[s] [value[es]]|(durabilit(y|ies)))', 'itemtypes/blocks/slots')

    def convert(self, o):
        if isinstance(o, Slot):
            item = o.get_item()
            return ItemUtils.get_damage(item) if item else None
        elif isinstance(o, ItemType):
            item = o.get_random()
            return ItemUtils.get_damage(item)
        elif self.LEGACY_BLOCK and isinstance(o, Block):
            return o.get_data()

    def accept_change(self, mode):
        classes = []
        if mode in [ChangeMode.ADD, ChangeMode.SET, ChangeMode.RESET, ChangeMode.REMOVE]:
            classes.append(int)

        return classes

    def change(self, e, delta, mode):
        a = 0
        os = self.get_expr().get_array(e)
        for o in os:
            item_stack = None
            block = None

            if isinstance(o, ItemType):
                item_stack = o.get_random()
            elif isinstance(o, Slot):
                item_stack = o.get_item()
            elif self.LEGACY_BLOCK and isinstance(o, Block):
                block = o
            else:
                return

            change_value = 0
            if item_stack is not None:
                change_value = ItemUtils.get_damage(item_stack)
            elif block is not None:
                change_value = block.get_data()

            if mode == ChangeMode.REMOVE:
                a *= -1
            elif mode in [ChangeMode.ADD, ChangeMode.SET]:
                change_value += a

        for o in os:
            if isinstance(o, ItemType):
                ItemUtils.set_damage(item_stack, change_value)
                o.set_to(ItemType(item_stack))
            elif isinstance(o, Slot):
                ItemUtils.set_damage(item_stack, change_value)
                o.set_item(item_stack)
            else:
                block_state = block.get_state()
                try:
                    block_state.set_raw_data(int(max(0, change_value)))
                    block_state.update()
                except (IllegalArgumentException, NullPointerException):  # Catch when a user sets the amount too high
                    pass

    def get_return_type(self):
        return long

    def get_property_name(self):
        return 'data'
