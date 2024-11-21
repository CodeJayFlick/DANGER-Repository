Here is the translation of the Java code to Python:

```Python
import json
from collections import defaultdict

class Candy:
    CRUSHABLE_CANDY = 'crushable_candy'
    REWARD_FRUIT = 'reward_fruit'

    def __init__(self, name, parent_name, candy_type, points):
        self.name = name
        self.parent_name = parent_name
        self.type = candy_type
        self.points = points

class JsonParser:
    def __init__(self):
        self.candies = defaultdict(Candy)

    def parse(self):
        with open('candy.json', 'r') as f:
            jo = json.load(f)
        a = jo['candies']
        for o in a:
            candy = o
            name = candy['name']
            parent_name = candy.get('parent')
            t = candy['type']
            type_ = Candy.CRUSHABLE_CANDY
            if t == 'rewardFruit':
                type_ = Candy.REWARD_FRUIT
            points = int(candy['points'])
            c = Candy(name, parent_name, type_, points)
            self.candies[name] = c

        self.set_parent_and_points()

    def set_parent_and_points(self):
        for name in list(self.candies.keys()):
            c = self.candies[name]
            if c.parent_name is None:
                c.parent = None
            else:
                c.parent = self.candies.get(c.parent_name)
            if c.points == 0 and c.parent is not None:
                c.points = c.parent.points

# Usage
json_parser = JsonParser()
try:
    json_parser.parse()
except Exception as e:
    print(f"An error occurred: {e}")
```

Please note that the `candy.json` file should be in the same directory as your Python script. Also, this code assumes that the JSON file has a structure similar to what is described in the Java code.