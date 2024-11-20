class SilenceEntity:
    def __init__(self):
        self.entities = None
        self.silence = False

    @staticmethod
    def register_effect():
        Skript.register_effect(SilenceEntity, 
            "silence %entities%", 
            "unsilence %entities%", 
            "make %entities% silent", 
            "make %entities% not silent")

    def init(self, exprs):
        self.entities = exprs[0]
        if len(exprs) > 1:
            self.silence = bool(int(exprs[1]))
        return True

    def execute(self, e):
        for entity in self.entities.get_array(e):
            entity.set_silent(self.silence)

    def __str__(self, e=None, debug=False):
        if self.silence:
            return "silence %s" % (self.entities)
        else:
            return "unsilence %s" % (self.entities)


# Register the effect
SilenceEntity.register_effect()
