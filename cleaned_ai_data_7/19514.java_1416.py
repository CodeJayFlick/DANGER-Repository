class ExprChunk:
    def __init__(self):
        self.locations = None

    @staticmethod
    def register_expression():
        Skript.register_expression(ExprChunk(), Chunk, "the chunk(s) (of|-directions%) %locations%", "%locations%'[s] chunks")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if matched_pattern == 0:
            self.locations = exprs[1]
            if exprs[0]:
                self.locations = Direction.combine(exprs[0], self.locations)
        else:
            self.locations = exprs[0]

    def get(self, e, source):
        return [l.get_chunk() for l in source]

    @property
    def return_type(self):
        return Chunk

    def __str__(self, e=None, debug=False):
        if not e and not debug:
            return "the chunk at %s" % self.locations
        else:
            return super().__str__()

    def accept_change(self, mode):
        if mode == ChangeMode.RESET:
            return []
        return None

    def change(self, e, delta, mode):
        assert mode == ChangeMode.RESET
        
        for c in self.get(e, []):
            c.world.regenerate_chunk(c.x, c.z)
