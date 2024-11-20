class CodeCompletion:
    def __init__(self, description: str, insertion: str = None, component: object = None):
        self.description = description
        self.insertion = insertion
        self.component = component

    @staticmethod
    def is_valid(completion: 'CodeCompletion') -> bool:
        return completion and completion.insertion is not None

    def get_component(self) -> object:
        return self.component

    def get_description(self) -> str:
        return self.description

    def get_insertion(self) -> str:
        return self.insertion

    def __str__(self) -> str:
        return f"CodeCompletion: '{self.get_description()}' ({self.get_insertion()})"

    def __lt__(self, other: 'CodeCompletion') -> bool:
        return self.description.lower() < other.description.lower()
