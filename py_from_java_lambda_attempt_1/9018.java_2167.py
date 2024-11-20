Here is the equivalent Python code:

```Python
class ScoreFilter:
    def __init__(self):
        self.name = "Score"
        self.min_value = 0.0
        self.max_value = 1.0

    def get_filterable_value(self, t):
        return getattr(t.get_similarity_score(), 'score')

    def create_empty_copy(self):
        return ScoreFilter()
```

Note that Python does not have direct equivalents to Java's `package`, `class` and `extends` keywords. The equivalent of a class in Python is simply defined using the `class` keyword, without any explicit inheritance declaration.

Also note that Python uses indentation (spaces or tabs) to denote block-level structure, rather than curly braces like Java does.