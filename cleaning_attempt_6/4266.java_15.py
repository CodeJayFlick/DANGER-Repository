import re

class FunctionFieldSearcher:
    def __init__(self, program, start_loc, address_set_view=None, forward=True, pattern=re.compile('')):
        self.program = program
        if address_set_view is not None:
            iterator = program.get_listing().get_functions(address_set_view, forward)
        else:
            iterator = program.get_listing().get_functions(start_loc.address(), forward)

    def advance(self):
        if iterator.has_next():
            function = next(iterator)
            if function and not function.is_external():
                return function.entry_point()
            find_matches_for_current_function(function)
            return None
        return None

    def find_matches_for_current_function(self, function):
        self.find_comment_matches(function)
        self.find_signature_matches(function)

    def find_variable_matches(self, function):
        parameters = function.get_parameters()
        for i in range(len(parameters)):
            check_type_string(parameters[i])
            check_name(parameters[i])
            check_storage(parameters[i])
            check_comment(parameters[i])

        local_variables = function.get_local_variables()
        for i in range(len(local_variables)):
            check_type_string(local_variables[i])
            check_name(local_variables[i])
            check_storage(local_variables[i])
            check_comment(local_variables[i])

    def find_signature_matches(self, function):
        signature = function.prototype_string(False, False)
        matcher = pattern.matcher(signature)
        address = function.entry_point()
        calling_convention_offset = FunctionUtils.get_calling_convention_signature_offset(function)

        while matcher.find():
            index = matcher.start()
            self.current_matches.append(FunctionSignatureFieldLocation(self.program, address, None, index + calling_convention_offset, signature))

    def find_comment_matches(self, function):
        if not hasattr(function, 'get_repeatable_comment'):
            return

        comment = function.get_repeatable_comment().replace('\n', ' ')
        matcher = pattern.matcher(comment)
        address = function.entry_point()

        while matcher.find():
            index = matcher.start()
            self.current_matches.append(get_function_comment_location(comment, index, address))

    def get_function_comment_location(self, comment, index, address):
        comments = StringUtilities.to_lines(comment)
        row_index = find_row_index(comments, index)
        char_offset = find_char_offset(index, row_index, comments)

        return FunctionRepeatableCommentFieldLocation(self.program, address, comments, row_index, char_offset)

    def find_char_offset(self, index, row_index, comment_strings):
        total_before_op_index = 0
        for i in range(row_index):
            total_before_op_index += len(comment_strings[i])
        return index - total_before_op_index

    def find_row_index(self, comment_strings, index):
        total_so_far = 0
        for i in range(len(comment_strings)):
            if index < total_so_far + len(comment_strings[i]):
                return i
        return len(comment_strings) - 1


class FunctionIterator:
    pass


def check_type_string(var):
    dt = None
    if isinstance(var, Parameter):
        dt = var.formal_data_type()
    else:
        dt = var.data_type()

    if dt is not None:
        search_string = dt.display_name()
        matcher = pattern.matcher(search_string)
        while matcher.find():
            index = matcher.start()
            self.current_matches.append(VariableTypeFieldLocation(self.program, var, index))


def check_name(var):
    search_string = var.name
    matcher = pattern.matcher(search_string)
    while matcher.find():
        index = matcher.start()
        self.current_matches.append(VariableNameFieldLocation(self.program, var, index))


def check_storage(var):
    search_string = str(var.variable_storage())
    matcher = pattern.matcher(search_string)
    while matcher.find():
        index = matcher.start()
        self.current_matches.append(VariableLocFieldLocation(self.program, var, index))


def check_comment(var):
    if not hasattr(var, 'comment'):
        return

    search_string = var.comment
    matcher = pattern.matcher(search_string)

    while matcher.find():
        index = matcher.start()
        self.current_matches.append(VariableCommentFieldLocation(self.program, var, index))
