class RemoveEquateCmd:
    def __init__(self, equate_names=None, tool=None):
        self.equate_names = equate_names if equate_names else []
        self.tool = tool
        self.msg = ""

    @property
    def name(self):
        return f"Remove Equate{'s' if len(self.equate_names) > 1 else ''}"

    def apply_to(self, obj):
        etable = (obj).get_equate_table()
        success = True
        for i in range(len(self.equate_names)):
            name = self.equate_names[i]
            if not etable.remove_equate(name):
                self.tool.set_status_info(f"Unable to remove equate: {name}")
                success = False
        if not success:
            self.msg = "Failed to remove one or more equates"
        return success

    @property
    def status_msg(self):
        return self.msg


# Example usage:

class Program:
    def get_equate_table(self):
        pass  # implement this method as needed


def main():
    tool = None  # implement this variable as needed
    cmd = RemoveEquateCmd(equate_names=["equate1", "equate2"], tool=tool)
    obj = Program()  # create an instance of the Program class
    success = cmd.apply_to(obj)
    print(cmd.status_msg)  # prints either "" or "Failed to remove one or more equates"


if __name__ == "__main__":
    main()
