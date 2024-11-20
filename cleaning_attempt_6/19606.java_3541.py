class LastColor:
    def __init__(self):
        self.name = "Last Color"
        self.description = "The colors used at the end of a string."
        self.examples = ["set {_color} to the last colors of \"<red>hey<blue>yo\""]
        self.since = "2.6"

    def convert(self, string):
        import colorama
        return str(colorama.Fore.getLastColors(string))

last_color = LastColor()
