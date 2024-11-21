class RelocationFactory:
    relocation_classes = [
        'RelocByIndexGroup',
        'RelocBySectDWithSkip',
        'RelocIncrPosition',
        'RelocLgByImport',
        'RelocLgRepeat',
        'RelocLgSetOrBySection',
        'RelocSetPosition',
        'RelocSmRepeat',
        'RelocUndefinedOpcode',
        'RelocationValueGroup'
    ]

    @staticmethod
    def get_relocation(reader):
        index = reader.get_pointer_index()
        for relocation_class in RelocationFactory.relocation_classes:
            try:
                constructor = getattr(__import__(relocation_class), relocation_class).get_constructor((BinaryReader,))
                relocation = constructor(new_object=[reader])
                if relocation.is_match():
                    return relocation
            except Exception as e:
                print(f"Unexpected Exception: {e.message}")
        reader.set_pointer_index(index)
        raise ValueError("No matching relocation found")
