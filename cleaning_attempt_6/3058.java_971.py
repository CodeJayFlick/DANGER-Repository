class InnerClassScript:
    def run(self):
        inner_class = MyInnerClass()
        print(inner_class.__str__())

        external_class = MyExternalClass()
        print(external_class.__str__())


class MyInnerClass:
    def __str__(self):
        return "I am an inner class."


class MyExternalClass:
    def __str__(self):
        return "I am an external class."
