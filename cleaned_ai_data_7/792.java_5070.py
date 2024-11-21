class DbgModelDefaultTargetModelRoot:
    def __init__(self, model: 'DbgModelImpl', type_hint: str):
        super().__init__(model, None, None, type_hint)

    def __init__(self, model: 'DbgModelImpl', type_hint: str, schema: 'TargetObjectSchema'):
        super().__init__(model, None, None, type_hint, schema)
