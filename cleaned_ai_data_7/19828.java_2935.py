class Adjective:
    DEFINITE_ARTICLE = -100
    DEFINITE_ARTICLE_TOKEN = "+"

    def __init__(self, key):
        self.key = key

    @property
    def genders(self):
        if not hasattr(self, '_genders'):
            self._genders = {}
        return self._genders

    @property
    def def_(self):
        if not hasattr(self, '_def_'):
            self._def_ = None
        return self._def_

    def on_value_change(self):
        self.genders.clear()
        v = self.value
        if v is None:
            return
        s = v.find('@')
        e = v.rfind('@')
        if s == -1:
            return
        if s == e:
            Skript.error(f"Invalid use of '@' in the adjective '{self.key}'")
            return
        self.def_ = v[:s] + v[e+1:]
        c = s
        while True:
            c2 = v.find('@', c+1)
            d = v.find(':', c+1)
            if d == -1 or d > c2:
                Skript.error(f"Missing colon (:) to separate the gender in the adjective '{self.key}' at index {c}: {v}")
                return
            gender = v[c+1:d]
            g = DEFINITE_ARTICLE_TOKEN == gender and Adjective.DEFINITE_ARTICLE or Noun.get_gender(g, self.key)
            if not self.genders.get(g):
                self.genders[g] = v[:s] + v[d+1:c2] + v[e+1:]
            c = c2

    def __str__(self):
        self.validate()
        return str(self.def_)

    def __str__(self, gender, flags):
        if (flags & Language.F_DEFINITE_ARTICLE) and DEFINITE_ARTICLE in self.genders:
            gender = Adjective.DEFINITE_ARTICLE
        elif (flags & Language.F_PLURAL):
            gender = Noun.PLURAL
        a = self.genders.get(gender)
        return a or str(self.def_)

    @staticmethod
    def to_string(adjectives, gender, flags, and=False):
        b = StringBuilder()
        for i in range(len(adjectives)):
            if i != 0:
                if i == len(adjectives) - 1:
                    b.append(" ").append(and and "and" or "or").append(" ")
                else:
                    b.append(", ")
            b.append(str(adjectives[i].toString(gender, flags)))
        return str(b)

    def to_string(self, n, flags):
        return n.to_string(self, flags)
