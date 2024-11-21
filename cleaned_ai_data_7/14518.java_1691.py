class Action:
    def __init__(self, title: str, description: str):
        self.title = title
        self.description = description

actions = [
    Action("hunted a rabbit", "arrives for dinner"),
    Action("tells a tale", "comes to listen"),
    Action("found gold", "takes his share of the gold"),
    Action("spotted enemies", "runs for cover"),
    Action("", "")
]

def get_description(action: str) -> str:
    if action == "":
        return ""
    else:
        return actions[actions.index(action)].description

print(get_description(actions[0].title))
