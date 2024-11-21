class OptionSection:
    def __init__(self, key):
        self.key = key

    def get(self, key: str) -> object:
        if isinstance(self, type(None)):
            return None
        
        key = key.lower()
        
        for field_name in dir(self.__class__):
            field = getattr(self.__class__, field_name)
            
            if hasattr(field, 'value'):
                try:
                    option = field.get(self)
                    
                    if str(option.key).lower() == key:
                        return option.value
                except (AttributeError, TypeError) as e:
                    pass
        
        return None

