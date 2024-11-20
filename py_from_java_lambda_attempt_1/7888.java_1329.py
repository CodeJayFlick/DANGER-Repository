Here is the translation of the given Java code into equivalent Python:

```Python
class MDQualifier:
    ANONYMOUS_NAMESPACE = "anonymous namespace"
    UNKNOWN_NAMESPACE = "MDMANG_UNK_QUALIFICATION"

    def __init__(self):
        pass

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def nameAnonymous(self):
        return self._nameAnonymous

    @nameAnonymous.setter
    def nameAnonymous(self, value):
        self._nameAnonymous = value

    @property
    def nameInterface(self):
        return self._nameInterface

    @nameInterface.setter
    def nameInterface(self, value):
        self._nameInterface = value

    @property
    def nameNested(self):
        return self._nameNested

    @nameNested.setter
    def nameNested(self, value):
        self._nameNested = value

    @property
    def nameNumbered(self):
        return self._nameNumbered

    @nameNumbered.setter
    def nameNumbered(self, value):
        self._nameNumbered = value

    @property
    def nameQ(self):
        return self._nameQ

    @nameQ.setter
    def nameQ(self, value):
        self._nameQ = value

    @property
    def isInterface(self):
        return self.nameInterface != None

    @property
    def isNested(self):
        return self.nameNested != None

    def insert(self, builder):
        if self.name:
            self.name.insert(builder)
        elif self.nameAnonymous:
            dmang.insertString(builder, MDQualifier.ANONYMOUS_NAMESPACE)
        elif self.nameInterface:
            self.nameInterface.insert(builder)
        elif self.nameNested:
            self.nameNested.insert(builder)
        elif self.nameNumbered:
            self.nameNumbered.insert(builder)
        elif self.nameQ:
            dmang.insertString(builder, self.nameQ)
        else:
            dmang.insertString(builder, MDQualifier.UNKNOWN_NAMESPACE)

    def parseInternal(self):
        if dmang.peek() == '?':
            switch = dmang.peek(1)
            if switch == '?':
                self.nameNested = MDReusableName(dmang)
                self.nameNested.parse()
            elif switch == '$':
                self.name = MDReusableName(dmang)
                self.name.parse()
            elif switch == 'A':  # Anonymous namespace
                dmang.parseInfoPush(0, "FragmentName from Anonymous Namespace")
                dmang.increment()  # skip the '?'
                self.nameAnonymous = MDReusableName(dmang)
                self.nameAnonymous.parse()
                dmang.parseInfoPop()
            elif switch == 'I':  # Believe this is interface namespace
                dmang.parseInfoPush(0, "InterfaceName from NameFragment")
                dmang.increment()  # skip the '?'
                dmang.increment()  # skip the 'I'
                self.nameInterface = MDReusableName(dmang)
                self.nameInterface.parse()
                dmang.parseInfoPop()
            elif switch == 'C':
                if dmang.processQualCAsSpecialFragment():
                    dmang.parseInfoPush(0, "NameC")
                    dmang.increment()  # skip the '?'
                    dmang.increment()  # skip the 'C'
                    MDFragmentName fragName = MDReusableName(dmang)
                    fragName.keepTerminator()
                    fragName.parse()
                    self.nameQ = fragName.toString()
                    dmang.parseInfoPop()
            elif switch in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
                # Whether or not intended (I don't think it was), for the cases other
                # than those that begin with '?' or 'I', undname processes all of these as numbered namespaces.
            elif switch == 'B':
                pass  # See note for 'A' anonymous namespace; for 'I' there is no evidence to include the 'I'
                    # in the fragment (investigation seems to have it removed).
            else:
                raise MDException("SpecialName not expected in qualification list")
        else:  # special name
            self.name = MDReusableName(dmang)
            self.name.parse()
```

Please note that Python does not support switch-case statements. The above code is written using if-elif ladder for the same purpose as Java's switch statement.