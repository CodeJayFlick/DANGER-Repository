class TagName:
    def __init__(self, name):
        self.name = name

def tag_name_of(name: str) -> 'TagName':
    return TagName(name)

