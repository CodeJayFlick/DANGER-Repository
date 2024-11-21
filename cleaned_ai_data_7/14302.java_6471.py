# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CatapultCommand:
    def process(self):
        view = CatapultView()
        view.display()

class Command:
    pass

class CatapultView:
    def display(self):
        # Your code to display the catapult goes here
        print("Catapult View Displayed")
