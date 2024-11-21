import re
from typing import List, Optional

class Documentation:
    def __init__(self):
        self.generate = Skript.testing() and os.path.exists(Skript.getInstance().getDataFolder() + "/generate-doc")

    @staticmethod
    def generate():
        if not Documentation.generate:
            return
        try:
            with open(os.path.join(Skript.getInstance().getDataFolder(), "doc.sql"), 'w') as f:
                pw = PrintWriter(f)
                self.as_sql(pw)
                pw.flush()
                pw.close()
        except (FileNotFoundError, UnsupportedEncodingException) as e:
            print(str(e))

    @staticmethod
    def convert_regex(regex: str, escape_html: bool = True):
        if re.search(r'[^a-zA-Z0-9\s]', regex):
            Skript.error(f"Regex '{regex}' contains unconverted Regex syntax")
        return f"[{re.sub(r'\((.+?)\)', lambda m: f'[{m.group(1)}]', regex, flags=re.DOTALL).replace('(', '[').replace(')', ']') if escape_html else regex

    @staticmethod
    def clean_patterns(patterns: str) -> str:
        return re.sub(r'(?<!\\)%(.+?)?(?<!\\)%', lambda m: f"[{m.group(1)}]", patterns, flags=re.DOTALL)

    @staticmethod
    def insert_syntax_element(pw: PrintWriter, info: SyntaxElementInfo):
        if not info.c.getAnnotation(Name.class).value():
            return
        desc = validate_html(info.getDescription(), "syntax elements")
        since = validate_html(str(info.getSince()), "syntax elements")
        if not (desc and since):
            Skript.warning(f"Syntax element '{info.getName()}' is missing information")

    @staticmethod
    def insert_event(pw: PrintWriter, info: SkriptEventInfo):
        for i in Skript.getEvents():
            if info.getId().equals(i.getId()):
                return

    @staticmethod
    def insert_class(pw: PrintWriter, info: ClassInfo):
        pass  # not implemented yet

    @staticmethod
    def as_sql(pw: PrintWriter):
        pw.println("-- syntax elements")
        for e in Skript.getExpressions():
            self.insert_syntax_element(pw, e)
        pw.println()
        pw.println("-- events")
        for i in Skript.getEvents():
            self.insert_event(pw, i)

    @staticmethod
    def validate_html(html: str, base_url: str) -> Optional[str]:
        if not html:
            return None

        # TO DO: implement validation logic here
        pass  # this is a placeholder for the actual implementation

# TO DO: implement Skript class and its methods (getInstance(), testing(), getDataFolder())
