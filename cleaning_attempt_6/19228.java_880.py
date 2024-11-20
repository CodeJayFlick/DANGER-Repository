class CondContains:
    def __init__(self):
        self.containers = None
        self.items = None
        self.explicit_single = False
        self.check_type = 'unknown'

    @staticmethod
    def register_condition():
        Skript.register_condition(CondContains, 
            ["%inventories% (has|have) %itemtypes% [in [(the[ir]|his|her|its)] inventory]", 
             "%inventories% (doesn't|does not|do not|don't) have %itemtypes% [in [(the[ir]|his|her|its)] inventory]", 
             "%inventories/strings/objects% contain[(1¦s)] %itemtypes/strings/objects%", 
             "%inventories/strings/objects% (doesn't|does not|do not|don't) contain %itemtypes/strings/objects%"
            )

    def init(self, exprs):
        self.containers = exprs[0]
        self.items = exprs[1]

        if len(exprs) == 2:
            self.explicit_single = True

        if len(exprs) <= 1:
            self.check_type = 'inventory'
        else:
            self.check_type = 'unknown'

    def check(self, e):
        container_values = self.containers.get_all(e)

        if not container_values:
            return self.is_negated()

        # Change checkType according to values
        if self.check_type == 'unknown':
            for value in container_values:
                if isinstance(value, Inventory):
                    self.check_type = 'inventory'
                    break
                elif (self.explicit_single and 
                      isinstance(value, str)):
                    self.check_type = 'string'
                    break
                else:
                    self.check_type = 'objects'

        if self.check_type == 'inventory':
            return SimpleExpression().check(container_values, lambda o: 
                inventory = Inventory(o)
                return self.items.check(e, lambda o1: 
                    if isinstance(o1, ItemType):
                        return (ItemType(o1)).is_contained_in(inventory)
                    elif isinstance(o1, ItemStack):
                        return inventory.contains(ItemStack(o1))
                    elif isinstance(o1, Inventory):
                        return o1 == inventory
                    else:
                        return False))

        elif self.check_type == 'string':
            case_sensitive = SkriptConfig.case_sensitive.value()

            return SimpleExpression().check(container_values, lambda o: 
                string = str(o)
                return self.items.check(e, lambda o1: 
                    if isinstance(o1, str):
                        return StringUtils.contains(string, str(o1), case_sensitive)
                    else:
                        return False))

        elif self.check_type == 'objects':
            assert self.check_type == 'objects'

            return self.items.check(e, lambda o1: 
                for value in container_values:
                    if Comparators.compare(o1, value) == Relation.EQUAL:
                        return True
                return False)

    def __str__(self):
        return f"{self.containers} {('does not' if self.is_negated() else ' ')}contain{('s' if len(self.items.get_all()) > 1 else '')} {self.items}"
