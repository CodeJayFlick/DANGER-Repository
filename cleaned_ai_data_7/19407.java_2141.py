class FallingBlockData:
    def __init__(self):
        self.types = None
    
    @staticmethod
    def register():
        EntityData.register(FallingBlockData, "falling block", FallingBlock)
    
    not_a_block_error = Message("entities.falling block.not a block error")
    adjective = Adjective("entities.falling block.adjective")

    def __init__(self, types=None):
        self.types = types

    @staticmethod
    def convert(types):
        if types is None:
            return []
        
        converted_types = []
        for t in types:
            new_type = ItemType(t.getBlock().clone())
            iter = new_type.iterator()
            while iter.has_next():
                id = iter.next().getType()
                if not id.is_block():
                    iter.remove()
            
            if len(new_type) == 0:
                return None
            
            new_type.set_amount(-1)
            new_type.set_all(False)
            new_type.clear_enchantments()
            converted_types.append(new_type)
        
        return converted_types

    def init(self, exprs):
        if len(exprs) > 0 and exprs[0] is not None:
            self.types = FallingBlockData.convert([exprs[0]])
            
            if self.types == []:
                Skript.error(self.not_a_block_error)
                return False
        
        return True

    def init(self, c):
        if c is not None:  # TODO material data support
            e = FallingBlock(c)
            self.types = [ItemType(BlockCompat.INSTANCE.falling_block_to_state(e))]
        
        return True

    def match(self, entity):
        if self.types is not None:
            for t in self.types:
                if t.is_of_type(BlockCompat.INSTANCE.falling_block_to_state(entity)):
                    return True
        
        return False

    @staticmethod
    def spawn(loc):
        random_type = CollectionUtils.get_random(FallingBlockData.convert(self.types))
        
        assert random_type is not None, "random type"
        
        i = random_type.get_random()
        
        if i is None or i.getType() == Material.AIR or not i.getType().is_block():
            return None
        
        return loc.getWorld().spawn_falling_block(loc, i.getType(), i.getDurability())

    def set(self):
        assert False

    @staticmethod
    def get_type():
        return FallingBlock

    def is_supertype_of(self, e):
        if not isinstance(e, FallingBlockData):
            return False
        
        d = e
        if self.types is None:
            return True
        
        if d.types is None:
            return False
        
        return ItemType.is_subset(self.types, d.types)

    @staticmethod
    def get_super_type():
        return FallingBlockData

    def __str__(self):
        types = self.types
        if types is None:
            return super().__str__()
        
        b = StringBuilder()
        b.append(Noun.get_article_with_space(types[0].get_types()[0].get_gender(), 1))
        b.append(self.adjective)
        b.append(" ")
        b.append(Classes.toString(types, False, False))
        
        return str(b)

    @staticmethod
    def deserialize(s):
        raise NotImplementedError("old serialization is not supported")

    def equals_i(self, obj):
        if not isinstance(obj, FallingBlockData):
            return False
        
        return self.types == ((FallingBlockData) obj).types

    def hash_code_i(self):
        return hash(self.types)
