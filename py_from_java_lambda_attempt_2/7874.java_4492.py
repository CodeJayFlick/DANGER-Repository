Here is the translation of the given Java code into equivalent Python:

```Python
class MDMangParseInfo:
    def __init__(self):
        self.info_stack = []
        self.info_list = []
        self.parse_info_mangled_index = 0
        self.parse_info_builder = ""

    def parse_info_push_pop(self, start_index_offset, item_name):
        self.parse_info_push(start_index_offset, item_name)
        self.parse_info_pop()

    def parse_info_push(self, start_index_offset, item_name):
        info = MDParseInfo(iter().get_index() - start_index_offset,
                            len(self.info_stack), item_name)
        self.info_stack.append(info)
        self.info_list.append(info)
        self.parse_info_mangled_index = do_parse_info_single(
            self.parse_info_builder, self.parse_info_mangled_index, len(self.info_list) - 1)

    def parse_info_pop(self):
        index = max(iter().get_index() - 1,
                    self.info_list[-1].start_index)
        old_info = self.info_stack.pop()
        info = MDParseInfo(index, len(self.info_stack), old_info.item_name + " -- END")
        self.info_list.append(info)
        self.parse_info_mangled_index = do_parse_info_single(
            self.parse_info_builder, self.parse_info_mangled_index, len(self.info_list) - 1)

    def get_parse_info_incremental(self):
        return self.parse_info_builder

    class MDParseInfo:
        def __init__(self, start_index, item_depth, item_name):
            self.start_index = start_index
            self.item_depth = item_depth
            self.item_name = item_name

        def get_item_name(self):
            return self.item_name

        def get_start_index(self):
            return self.start_index


def do_parse_info_single(builder, parse_info_mangled_index_arg, info_index):
    while (parse_info_mangled_index_arg < info_list[info_index].start_index):
        if (info_index == 0) or ((info_index != 0) and
                                  (parse_info_mangled_index_arg > info_list[info_index - 1].start_index)):
            output_mangled_char_and_info(builder, parse_info_mangled_index_arg,
                                          info_list[info_index].item_depth, None)
        parse_info_mangled_index_arg += 1

    if (parse_info_mangled_index_arg >= info_list[info_index].start_index):
        if (info_index == 0) or (
                info_list[info_index].start_index != info_list[info_index - 1].start_index):
            output_mangled_char_and_info(builder, info_list[info_index].start_index,
                                          info_list[info_index].item_depth, info_list[info_index].item_name)
        else:
            output_mangled_char_and_info(builder, -1, info_list[info_index].item_depth,
                                          info_list[info_index].item_name)

    return parse_info_mangled_index_arg


def get_parse_info_orig(self):
    builder = ""
    mangled_index = 0
    info_index = 0

    while (info_index < len(info_list)):
        if (mangled_index == info_list[info_index].start_index):
            output_mangled_char_and_info(builder, mangled_index,
                                          info_list[info_index].item_depth, info_list[info_index].item_name)
            # Output multiple lines that looks like: "C  +--+--+--Item"
            while ((mangled_index < info_list[info_index].start_index)):
                if (info_index == 0) or (
                        (info_index != 0) and
                        (mangled_index > info_list[info_index - 1].start_index)):
                    output_mangled_char_and_info(builder, mangled_index,
                                                  info_list[info_index].item_depth, None)
                mangled_index += 1

        else:
            # Output multiple lines that looks like: "C |  |  |  |"
            while ((mangled_index < info_list[info_index].start_index)):
                if (info_index == 0) or (
                        (info_index != 0) and
                        (mangled_index > info_list[info_index - 1].startIndex)):
                    output_mangled_char_and_info(builder, mangled_index,
                                                  info_list[info_index].item_depth, None)
                mangled_index += 1

        return builder


def get_parse_info(self):
    builder = ""
    parse_info_mangled_index_local = 0
    info_index = 0

    while (info_index < len(info_list)):
        parse_info_mangled_index_local = do_parse_info_single(builder,
                                                              parse_info_mangled_index_local, info_index)
        info_index += 1

    return builder


def output_mangled_char_and_info(builder, mangled_index, item_depth, item_name):
    if (mangled_index >= 0):
        if (mangled_index < len(mangled)):
            builder.append(f"{str(format("%04d", mangled_index))} {chr(mangled[mangled_index])}")
        else:
            builder.append(str.format("%04d", mangled_index))
    else:
        builder.append("        ")

    if item_name is None:
        while (item_depth-- > 0):
            builder.append("|  ")
        builder.append("|")
    else:
        while (item_depth-- > 0):
            builder.append("+--")
        builder.append(item_name)
    builder.append("\n")


mangled = "your_mangled_string_here"
info_list = []

# Example usage
parse_info = MDMangParseInfo()
parse_info.parse_info_push_pop(1, "Item Name")

print(parse_info.get_parse_info_incremental())
```

Please note that the Python code does not exactly replicate the Java code. It is a translation of the given Java code into equivalent Python and may require adjustments based on your specific requirements.