class ScoreFilter:
    def __init__(self):
        self.name = "Score"
        self.min_value = 0.0
        self.max_value = 1.0

    def get_filterable_value(self, t):
        return getattr(t.get_similarity_score(), 'score')

    def create_empty_copy(self):
        return ScoreFilter()
