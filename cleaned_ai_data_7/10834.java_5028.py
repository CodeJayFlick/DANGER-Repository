class RelayoutOption:
    ALWAYS = ("Always",)
    BLOCK_MODEL_CHANGES = ("Block Model Changes Only",)
    VERTEX_GROUPING_CHANGES = ("Vertex Grouping Changes Only",)
    NEVER = ("Never",)

    def __init__(self, display_name):
        self.display_name = display_name

    def __str__(self):
        return self.display_name
