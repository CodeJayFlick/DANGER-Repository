class FunctionTag:
    def __init__(self):
        self._id = None
        self._name = None
        self._comment = None

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value):
        self._comment = value

    def get_id(self):
        """Returns the id of the item"""
        return self.id

    def get_name(self):
        """Returns the tag name"""
        return self.name

    def get_comment(self):
        """Returns the tag comment"""
        return self.comment

    def set_name(self, name):
        """Sets the name of the tag"""
        self.name = name

    def set_comment(self, comment):
        """Sets the comment for this tag"""
        self.comment = comment

    def delete(self):
        """Deletes this tag from the program """
        pass  # This method does not have a direct equivalent in Python
