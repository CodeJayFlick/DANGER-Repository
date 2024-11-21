class JavaSourceFile:
    def __init__(self, filename):
        self.filename = filename
        self.lines_list = []
        self.initial_line_count = 0
        self.load_file()

    # copy constructor
    def __copy__(self, original_lines):
        this.filename = self.filename
        this.lines_list.extend(original_lines)
        this.initial_line_count = len(self.lines_list)

    def load_file(self):
        try:
            with open(self.filename) as reader:
                newline = '\n'
                line_number = 0
                for line in reader.readlines():
                    if not line.strip(): continue
                    self.lines_list.append(JavaSourceLine(line + newline, line_number))
                    line_number += 1

        except FileNotFoundError as e:
            print(e)
        except Exception as e:
            print(e)

    def has_changes(self):
        return len(self.lines_list) != self.initial_line_count or any(line.has_changes() for line in self.lines_list)

    def get_import_section_start_line_number(self):
        for line in self.lines_list:
            if line.text.strip().startswith("import"):
                return line.line_number
        return -1

    def get_line_after_statement_at_line(self, line_number):
        start_line = self.get_statement_start_for_line(line_number)
        if start_line.text.strip().endswith(";"):
            return line_number + 1

        statement_lines = self.get_remaining_lines_for_statement(start_line, start_line.line_number + 1)
        last_line = statement_lines[-1]
        return last_line.line_number + 1

    def remove_java_statement(self, line_number):
        start_line = self.get_statement_start_for_line(line_number)
        if start_line.text.strip().endswith(";"):
            start_line.delete()
            return
        lines_to_clear = list(self.get_remaining_lines_for_statement(start_line, start_line.line_number + 1))
        for i in range(len(lines_to_clear) - 1):
            lines_to_clear[i].delete()

    def get_remaining_lines_for_statement(self, statement_start, line_number):
        paren_matcher = TokenPairMatcher('(', ')')
        brace_matcher = TokenPairMatcher('{', '}')
        text = statement_start.text
        paren_matcher.scan_line(text)
        brace_matcher.scan_line(text)

        lines_list = list(self.lines_list[line_number - 1:])
        for line in lines_list:
            if not self.is_valid_end_of_statement(paren_matcher, brace_matcher, line):
                return lines_list[:line.line_number]
        return lines_list

    def is_valid_end_of_statement(self, paren_matcher, brace_matcher, line):
        text = line.text
        paren_matcher.scan_line(text)
        brace_matcher.scan_line(text)

        if not paren_matcher.is_balanced() or not brace_matcher.is_balanced():
            return False

        return text.strip().endswith(";")

    def get_statement_start_for_line(self, line_number):
        last_line = self.get_statement_from_next_semicolon(line_number)
        if last_line:
            return last_line
        current_line = self.lines_list[line_number - 1]
        while True:
            equals_matcher = TokenMatcher('=')
            semicolon_matcher = TokenMatcher(';')
            text = current_line.text
            equals_matcher.scan_line(text)
            if equals_matcher.found_token():
                return current_line

            semicolon_matcher.scan_line(text)
            if semicolon_matcher.found_token() and line_number != 1:
                return self.find_next_non_blank_line(line_number)

    def get_statement_from_next_semicolon(self, line_number):
        last_line = None
        while True:
            current_line = self.lines_list[line_number - 1]
            if not current_line.text.strip().endswith(";"):
                break

            text = current_line.text
            paren_matcher = TokenPairMatcher('(', ')')
            brace_matcher = TokenPairMatcher('{', '}')
            paren_matcher.scan_line(text)
            brace_matcher.scan_line(text)

            equals_matcher = TokenMatcher('=')
            semicolon_matcher = TokenMatcher(';')

            if text.contains("serialVersion"):
                continue

            while True:
                current_line = self.lines_list[line_number - 1]
                line_text = current_line.text
                paren_matcher.scan_line(line_text)
                brace_matcher.scan_line(line_text)

                equals_matcher.scan_line(line_text)
                semicolon_matcher.scan_line(line_text)

                if semicolon_matcher.found_token() and last_line:
                    return self.find_next_non_blank_line(line_number + 1)

                line_number += 1

    def is_valid_statement(self, last_line):
        text = last_line.text.strip()
        if not text.endswith(";"):
            return False

        paren_matcher = TokenPairMatcher('(', ')')
        brace_matcher = TokenPairMatcher('{', '}')
        paren_matcher.scan_line(text)
        brace_matcher.scan_line(text)

        return paren_matcher.is_balanced() and brace_matcher.is_balanced()

    def contains_action_assignment(self, text):
        equals_parts = text.split("=")
        left_hand_side = equals_parts[0]
        name_and_maybe_declaration = left_hand_side.strip().split("\\s")
        if len(name_and_maybe_declaration) == 2:
            return name_and_maybe_declaration[0].endswith("Action")

        return any(contains_action_assignment(part) for part in name_and_maybe_declaration)

    def find_end_of_unknown_line(self, line_number):
        current_line = self.lines_list[line_number - 1]
        while True:
            if not current_line.text.strip().endswith(";"):
                break

            text = current_line.text
            paren_matcher = TokenPairMatcher('(', ')')
            brace_matcher = TokenPairMatcher('{', '}')
            paren_matcher.scan_line(text)
            brace_matcher.scan_line(text)

            return self.lines_list[line_number - 1]

    def find_next_non_blank_line(self, line_number):
        while True:
            current_line = self.lines_list[line_number - 1]
            if not current_line.text.strip():
                break

            return current_line

    def get_line(self, one_based_line_number):
        try:
            return JavaSourceLine(self.lines_list[one_based_line_number - 2].text, one_based_line_number)
        except IndexError as e:
            raise IndexOutOfBoundsException("File does not contain line number: " + str(one_based_line_number))

    def save(self):
        if not self.has_changes():
            print("\tno changes to: " + self.filename)

        try:
            with open(self.filename, 'w') as file_writer:
                for line in self.lines_list:
                    file_writer.write(line.text)
        except Exception as e:
            print(e)


class JavaSourceLine:
    def __init__(self, text, line_number):
        self.text = text
        self.line_number = line_number

    @property
    def has_changes(self):
        return False  # This is not implemented in the original code


class TokenMatcher:
    def __init__(self, token):
        self.token = token
        self.found_token = False

    def scan_line(self, text):
        if self.found_token: return
        for char in text:
            if char == self.token:
                self.found_token = True
                break


class TokenPairMatcher(TokenMatcher):
    def __init__(self, left_token, right_token):
        super().__init__(left_token)
        self.right_token = right_token

    @property
    def is_balanced(self):
        return not self.found_token  # This property does not make sense for a token pair matcher


class JavaSourceFileCopy(JavaSourceFile):
    def __copy__(self, original_lines):
        super().__init__(self.filename, original_lines)
