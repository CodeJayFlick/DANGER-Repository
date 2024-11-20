class DefaultTargetModelRoot:
    def __init__(self, model: 'AbstractDebuggerObjectModel', type_hint: str):
        self.__init__(model, type_hint, TargetObjectSchema.OBJECT)

    def __init__(self, model: 'AbstractDebuggerObjectModel', type_hint: str, schema: 'TargetObjectSchema'):
        super().__init__(model, None, None, type_hint, schema)
