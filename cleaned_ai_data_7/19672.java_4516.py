class ScoreboardTags:
    def __init__(self):
        pass

    @property
    def entities(self):
        return self._entities

    @entities.setter
    def entities(self, value):
        self._entities = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) > 0:
            self.entities = exprs[0]
        return True

    def get(self, e):
        tags = [tag for entity in self.entities.get_array(e) for tag in entity.scoreboard_tags()]
        return tags

    def accept_change(self, mode):
        if mode in ['set', 'add', 'remove', 'delete']:
            return [str]
        else:
            return None

    def change(self, e, delta, mode):
        for entity in self.entities.get_array(e):
            if mode == 'set':
                entity.scoreboard_tags().clear()
                for tag in delta:
                    entity.add_scoreboard_tag(tag)
            elif mode == 'add':
                for tag in delta:
                    entity.add_scoreboard_tag(tag)
            elif mode == 'remove':
                for tag in delta:
                    entity.remove_scoreboard_tag(tag)
            else:  # reset or delete
                entity.scoreboard_tags().clear()

    def is_single(self):
        return False

    def get_return_type(self):
        return str

    def __str__(self, e=None, debug=False):
        if e and debug:
            return f"the scoreboard tags of {self.entities}"
        else:
            return "scoreboard tags"
