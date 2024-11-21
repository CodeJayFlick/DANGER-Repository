class ExprNamed:
    def __init__(self):
        self.name = None

    @staticmethod
    def register_expression():
        Skript.register_expression(ExprNamed)

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) != 2:
            return False
        self.set_expr(exprs[0])
        self.name = exprs[1]
        return True

    def get(self, e, source):
        name = self.name.get_single(e)
        if name is None:
            return [obj for obj in source]  # No name provided, do nothing
        result = []
        for obj in source:
            if isinstance(obj, InventoryType):
                inventory = Bukkit.create_inventory(None, obj, name)
                result.append(inventory)
            elif isinstance(obj, ItemStack):
                stack = obj.clone()
                meta = stack.get_item_meta()
                if meta is not None:
                    meta.set_display_name(name)
                    stack.set_item_meta(meta)
                result.append(stack)
            else:  # assume it's an ItemType
                item = obj.clone()
                meta = item.get_item_meta()
                if meta is not None:
                    meta.set_display_name(name)
                    item.set_item_meta(meta)
                result.append(item)
        return result

    def get_return_type(self):
        return self.get_expr().get_return_type()

    def __str__(self, e=None, debug=False):
        return f"{super().__str__(e, debug)} named {self.name}"
