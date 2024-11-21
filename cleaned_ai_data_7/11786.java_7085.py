class Yylval:
    def __init__(self):
        self.sym = None  # SleighSymbol
        self.spacesym = None  # SpaceSymbol
        self.tokensym = None  # TokenSymbol
        self.useropsym = None  # UserOpSymbol
        self.valuesym = None  # ValueSymbol
        self.valuemapsym = None  # ValueMapSymbol
        self.namesym = None  # NameSymbol
        self.varsym = None  # VarnodeSymbol
        self.bitsym = None  # BitrangeSymbol
        self.varlistsym = None  # VarnodeListSymbol
        self.operandsym = None  # OperandSymbol
        self.startsym = None  # StartSymbol
        self.endsym = None  # EndSymbol
        self.subtablesym = None  # SubtableSymbol
        self.macrosym = None  # MacroSymbol
        self.labelsym = None  # LabelSymbol
        self.specsym = None  # SpecificSymbol
        self.contextsym = None  # ContextSymbol

# No imports needed here, as this is a simple class definition.
