class Money:
    def __init__(self, amount):
        self.amount = amount

    @staticmethod
    def parse(s):
        if VaultHook.economy is None:
            return None
        
        singular = VaultHook.economy.currency_name_singular()
        plural = VaultHook.economy.currency_name_plural()

        if plural and not plural.strip().endswith(''):
            if s.lower().strip().endswith(plural.lower()):
                try:
                    amount = float(s[:-len(plural)].strip())
                    return Money(amount)
                except ValueError: pass
            elif s.lower().startswith(plural.lower()):
                try:
                    amount = float(s[len(plural):].strip())
                    return Money(amount)
                except ValueError: pass
        
        if singular and not singular.strip().endswith(''):
            if s.lower().strip().endswith(singular.lower()):
                try:
                    amount = float(s[:-len(singular)].strip())
                    return Money(amount)
                except ValueError: pass
            elif s.lower().startswith(singular.lower()):
                try:
                    amount = float(s[len(singular):].strip())
                    return Money(amount)
                except ValueError: pass
        
        #try:
        #    return Money(float(s))
        #except ValueError: pass

        return None
    
    def __str__(self):
        return f"{VaultHook.economy.format(self.amount)}"
