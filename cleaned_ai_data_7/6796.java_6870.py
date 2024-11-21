class DecompilerInitializer:
    def run(self):
        CommentsActionFactory.register(DecompilerCommentsActionFactory())

    @property
    def name(self):
        return "Decompiler Module"
