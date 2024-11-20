class AliasesMap:
    class Match:
        def __init__(self, quality: 'MatchQuality', data: 'AliasData' = None):
            self.quality = quality
            self.data = data

        @property
        def get_quality(self) -> 'MatchQuality':
            return self.quality

        @property
        def get_data(self) -> 'AliasData':
            return self.data

    class AliasData:
        def __init__(self, item: 'ItemData', name: str, minecraft_id: str, related_entity: 'EntityData' = None):
            self.item = item
            self.name = name
            self.minecraft_id = minecraft_id
            self.related_entity = related_entity

        @property
        def get_item(self) -> 'ItemData':
            return self.item

        @property
        def get_name(self) -> str:
            return self.name

        @property
        def get_minecraft_id(self) -> str:
            return self.minecraft_id

        @property
        def get_related_entity(self) -> 'EntityData':
            return self.related_entity

    class MaterialEntry:
        def __init__(self):
            self.default_item = None
            self.items = []

    material_entries = [MaterialEntry() for _ in range(len(Material))]

    def __init__(self):
        self.clear()

    @property
    def get_entry(self, item: 'ItemData') -> MaterialEntry:
        return self.material_entries[item.get_type().ordinal()]

    def add_alias(self, data: 'AliasData'):
        entry = self.get_entry(data.get_item())
        if data.get_item().is_default():
            entry.default_item = data
        else:
            entry.items.append(data)

    @property
    def match_alias(self, item: 'ItemData') -> Match:
        entry = self.get_entry(item)
        if entry.default_item is None and not entry.items:
            return Match(MatchQuality.DIFFERENT, None)
        
        max_quality = MatchQuality.DIFFERENT
        best_match = None
        for data in entry.items:
            quality = item.match_alias(data.get_item())
            if quality.is_better(max_quality):
                max_quality = quality
                best_match = data
        
        if max_quality.is_better(MatchQuality.SAME_MATERIAL):
            assert best_match is not None  # Re-setting quality sets this too
            return Match(max_quality, best_match)
        else:
            default_item = entry.default_item
            if default_item is not None:  # Just match against it
                return Match(item.match_alias(default_item.get_item()), default_item)
            elif best_match is not None:  # Initially ignored this, but it is best match
                return Match(MatchQuality.SAME_MATERIAL, best_match)

        raise AssertionError()  # Shouldn't have reached here

    @property
    def exact_match(self, item: 'ItemData') -> Match:
        entry = self.get_entry(item)
        
        if entry.default_item is None and not entry.items:
            return Match(MatchQuality.DIFFERENT, None)

        for data in entry.items:
            if item.match_alias(data.get_item()) == MatchQuality.EXACT:
                return Match(MatchQuality.EXACT, data)

        return Match(MatchQuality.DIFFERENT, None)

    def clear(self):
        self.material_entries = [MaterialEntry() for _ in range(len(Material))]
