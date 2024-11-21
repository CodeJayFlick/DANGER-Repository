Here is the translation of the Java code to Python:
```
class ParsingEnvironment:
    def __init__(self, env=None):
        self.locator = Locator() if env is None else env.locator
        self.writer = LineArrayListWriter() if env is None else env.writer
        self.children = set()
        if env is not None:
            self.children.add(self)

    @property
    def lexing_errors(self):
        return self._lexing_errors

    @lexing_errors.setter
    def lexing_errors(self, value):
        self._lexing_errors = value

    @property
    def parsing_errors(self):
        return self._parsing_errors

    @parsing_errors.setter
    def parsing_errors(self, value):
        self._parsing_errors = value

    def get_lexing_errors(self):
        return self.lexing_errors + sum(child.lexing_errors for child in self.children)

    def get_parsing_errors(self):
        return self.parsing_errors + sum(child.parsing_errors for child in self.children)

    def lexing_error(self):
        self.lexing_errors += 1

    def parsing_error(self):
        self.parsing_errors += 1

    @property
    def locator(self):
        return self._locator

    @locator.setter
    def locator(self, value):
        self._locator = value

    @property
    def writer(self):
        return self._writer

    @writer.setter
    def writer(self, value):
        self._writer = value

    def get_error_header(self, e):
        if e.node is not None:
            try:
                e = ((CommonErrorNode) e.node).trappedException
            except ClassCastException:
                pass  # ignore for now
        location = self.locator.get_location(e.line)
        if location is None:
            return "UNKNOWN LOCATION (uncorrelated parser line {})".format(e.line)
        if location.lineno < 0:
            print("whoa, line <", 0)
        return "{}:{}".format(location.filename, location.lineno)

    def get_lexer_error_message(self, e, token_names):
        self.lexing_error()
        return self.get_error_message(e, token_names, self.writer)

    def get_parser_error_message(self, e, token_names):
        self.parsing_error()
        return self.get_error_message(e, token_names, self.writer)

    @staticmethod
    def NEWLINE():
        return "\n"

    def get_error_message(self, e, token_names, writer):
        lineno = e.line
        charpos = e.char_position_in_line
        if e.node is not None:
            try:
                e = ((CommonErrorNode) e.node).trappedException
            except ClassCastException:
                pass  # ignore for now
        msg = e.message
        if isinstance(e, UnwantedTokenException):
            ute = (UnwantedTokenException) e
            token_name = "<unknown>"
            if ute.expecting == Token.EOF:
                token_name = "EOF"
            else:
                token_name = token_names[ute.expecting]
            msg = "extraneous input {} expecting {}".format(get_token_error_display(ute.get_unexpected_token()), token_name)
        elif isinstance(e, MissingTokenException):
            mte = (MissingTokenException) e
            if mte.expecting == Token.EOF:
                msg = "unexpected token: {}".format(get_token_error_display(e.token))
            else:
                msg = "missing {}, unexpected {} at {}".format(token_names[mte.get_missing_type()], token_names[mte.get_unexpected_type()], get_token_error_display(e.token))
        elif isinstance(e, MismatchedTokenException):
            mte = (MismatchedTokenException) e
            if mte.token is None:
                msg = "expecting '{}', unexpected character: '{}'".format(((char) mte.expecting), ((char) mte.c))
            else:
                msg = "expecting {}, unexpected token: {}".format(token_names[mte.expecting], get_token_error_display(e.token))
        elif isinstance(e, MismatchedTreeNodeException):
            mtne = (MismatchedTreeNodeException) e
            token_name = "<unknown>"
            if mtne.expecting == Token.EOF:
                token_name = "EOF"
            else:
                token_name = token_names[mtne.expecting]
            msg = "mismatched tree node: {} expecting {}".format(mtne.node, token_name)
        elif isinstance(e, NoViableAltException):
            nvae = (NoViableAltException) e
            if e.token is None:
                msg = "unexpected text"
            else:
                if nvae.c == -1:
                    msg = "no viable alternative on EOF (missing semi-colon after this?)"
                else:
                    msg = "no viable alternative on {} at {}".format(token_names[nvae.c], get_token_error_display(e.token))
        elif isinstance(e, EarlyExitException):
            # for development, can add "(decision={})".format(eee.decisionNumber)
            msg = "required (...)+ loop did not match anything at input {}".format(get_token_error_display(e.token))
        elif isinstance(e, MismatchedSetException):
            mse = (MismatchedSetException) e
            msg = "mismatched input {} expecting set {}".format(get_token_error_display(e.token), mse.expecting)
        elif isinstance(e, MismatchedNotSetException):
            mse = (MismatchedNotSetException) e
            msg = "mismatched input {} expecting set {}".format(get_token_error_display(e.token), mse.expecting)
        elif isinstance(e, FailedPredicateException):
            fpe = (FailedPredicateException) e
            msg = "rule {} failed predicate: {{}}?".format(fpe.rule_name)

        line = "<internal error fetching line>"
        try:
            line = remove_preprocessor(ANTLRUtil.get_line(writer, lineno))
        except Exception as e1:
            print("Error:", str(e1))

        position = ANTLRUtil.tab_compensate(line, charpos)
        return "{}:{}{}".format(msg, self.locator.get_location(lineno).filename, ParsingEnvironment.NEWLINE())

    def remove_preprocessor(self, line):
        return line.replace("\b.*?\b", "")

    @staticmethod
    def get_token_error_display(t):
        if t is None:
            return "(null)"
        s = t.text
        if s is None:
            if t.type == Token.EOF:
                s = "<EOF>"
            else:
                s = "<{}>".format(t.type)
        s = s.replace("\n", "\\n")
        s = s.replace("\r", "\\r")
        s = s.replace("\t", "\\t")
        return "'{}'".format(s)

    def format(self, be):
        if self.lexing_errors > 0:
            if self.parsing_errors > 0:
                return "{}: {} lexing errors, {} parsing errors".format(be.message, self.lexing_errors, self.parsing_errors)
            else:
                return "{}: {} lexing errors".format(be.message, self.lexing_errors)
        elif self.parsing_errors > 0:
            return "{}: {} parsing errors".format(be.message, self.parsing_errors)
        else:
            return be.message
```
Note that I've used the `@property` decorator to create read-only properties for `lexing_errors`, `parsing_errors`, and other attributes. This is equivalent to using Java's getter/setter methods.

I've also replaced the `getLineArrayListWriter()` method with a simple constructor argument, since it seems like this was intended as an alternative way of creating instances of `ParsingEnvironment`.

Finally, I've removed some of the commented-out code that seemed irrelevant or unnecessary. Let me know if you have any further questions!