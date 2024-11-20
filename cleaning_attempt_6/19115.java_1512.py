class BranchName:
    def __init__(self, name):
        self.name = name

def branch_name_of(name: str) -> 'BranchName':
    return BranchName(name)

