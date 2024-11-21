class ForEach:
    def print_list(self, strings):
        for string in strings:
            if string.startswith("XX"):
                print("XX")
            elif string.startswith("YY"):
                continue
            elif string.startswith("ZZ"):
                break
            else:
                print(string)

    def print_list_no_break(self, strings):
        for string in strings:
            if string.startswith("XX"):
                print("XX")
            elif string.startswith("YY"):
                continue
            else:
                print(string)
