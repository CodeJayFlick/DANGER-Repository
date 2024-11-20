import random

class CondIsSlimeChunk:
    CHUNK_METHOD_EXISTS = hasattr(Chunk, 'isSlimeChunk')

    @classmethod
    def register(cls):
        import ch.njol.skript.util.log as log
        log.info('Registering condition: Is Slime Chunk')
        skript.register_condition(cls)

    def check(self, chunk):
        if self.CHUNK_METHOD_EXISTS:
            return chunk.isSlimeChunk()
        
        random.seed(chunk.world.get_seed() + 
                    (0x4c1906 * chunk.x * chunk.x) + 
                    (0x5ac0db * chunk.x) + 
                    (0x4307a7 * chunk.z * chunk.z) + 
                    ((0x5f24f *chunk.z) ^ 0x3ad8025f))
        return random.randint(1,10) == 0

    def get_property_name(self):
        return 'slime chunk'

# Register the condition
CondIsSlimeChunk.register()
