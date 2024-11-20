class LocationExpression:
    def __init__(self):
        self.name = "Location"
        self.description = ["The location of a block or entity.", 
                             "Please note that the location of an entity is at it' feet, use head location to get the location of the head."]
        self.examples = [
            "set {home::%uuid of player%} to the location of the player",
            "message \"You home was set to %player's location% in %player's world%.\""
        ]

    def init(self):
        return True

    def __str__(self, debug=False):
        if debug:
            return f"the location of {get_expr()}"
        else:
            return "the location"

def get_expr():
    # implement this function to retrieve the expression
    pass

# usage example:

expr = LocationExpression()
print(expr.name)
print(expr.description[0])
print(expr.examples[1])

