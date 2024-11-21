import jdom.output.Format
from jdom.output import XMLOutputter, TextMode

class GenericXMLOutputter(XMLOutputter):
    DEFAULT_INDENT = "     "

    def __init__(self):
        self.init()

    def init(self):
        # this prevents an excess build up of whitespace
        compact_format = Format.getCompactFormat()
        compact_format.set_indent(DEFAULT_INDENT)
        compact_format.setTextMode(TextMode.NORMALIZE)
        self.set_format(compact_format)

# Example usage:
outputter = GenericXMLOutputter()
