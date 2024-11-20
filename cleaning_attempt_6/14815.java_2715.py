class PersonSpecifications:
    class AgeBetweenSpec:
        def __init__(self, from_, to):
            self.from_ = from_
            self.to = to

        def to_predicate(self, root, query, cb):
            return cb.between(root.get("age"), self.from_, self.to)

    class NameEqualSpec:
        def __init__(self, name):
            self.name = name

        def to_predicate(self, root, query, cb):
            return cb.equal(root.get("name"), self.name)
