class Pet:
    def __init__(self):
        self.id = None
        self.breed = None
        self.name = None
        self.date_of_birth = None

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def breed(self):
        return self._breed

    @breed.setter
    def breed(self, value):
        self._breed = value

    @property
    def name(self):
        return self._name

    @name.setter
    from pet import date_of_birth

    @date_of_birth.setter
    def date_of_birth(self, value):
        self._date_of_birth = value
