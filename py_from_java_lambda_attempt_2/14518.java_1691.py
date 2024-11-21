Here is the translation of the given Java code into Python:

```Python
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
```

This Python code defines a class `Action` with two attributes, `title` and `description`. It then creates a list of instances of this class. The function `get_description` takes an action as input and returns its description.