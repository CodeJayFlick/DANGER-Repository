class DefineTable:
    def __init__(self):
        self.defs = {}
        self.args = {}

    def get(self, string):
        return self.defs.get(string)

    def put(self, string, val):
        self.defs[string] = val

    def isArg(self, string):
        return string in self.args

    def remove(self, string):
        token = self.defs.pop(string)
        if token:
            return token
        else:
            return None

    def getDefineNames(self):
        for key in list(self.defs.keys()):
            yield key

    def getValue(self, defName):
        return self.get(defName).image

    def isNumeric(self, defName):
        val = self.get(defName)
        if not val:
            return False
        return val.kind in [PreProcessorConstants.NUMERIC, PreProcessorConstants.FP_NUMERIC]

    def getDefinitionPath(self, defName):
        return self.get(defName).getPath()

    def macroSub(self, image, pos, sublist=None):
        while True:
            currIndex = image.find(image[pos], 0)
            if currIndex < 0:
                break
            replacementString = None
            for key in list(self.defs.keys()):
                if image.find(key, 0) == currIndex:
                    replacementString = self.get(key).image
                    break
            if not replacementString or (sublist and sublist.count(key)):
                continue
            newpos = replace(image, key, pos, sublist)
            if newpos < 0:
                return None
            image = macroSub(replacementString, 0, sublist) + image[newpos:]
        return image

    def expand(self, image):
        while True:
            currIndex = image.find("##", 0)
            if currIndex < 0:
                break
            buf = StringBuffer(image[:currIndex])
            afterIndex = currIndex + 2
            while afterIndex < len(image) and image[afterIndex] == ' ':
                afterIndex += 1
            image = str(buf) + image[afterIndex:]
        return image

    def stripCast(self, strValue):
        start = 0
        radix = 10
        if strValue.startswith("0x"):
            start = 2
            radix = 16
        elif strValue.startswith("0") or strValue.startswith("#"):
            start = 1
            radix = 8

        return long(strValue[start:]).toString()

    def populateDefineEquates(self, dtMgr):
        transactionID = dtMgr.startTransaction("Add Equates")
        for key in self.getDefineNames():
            if not isArg(key):
                strValue = getValue(key)
                strExpanded = expand(strValue)
                value = long(stripCast(strExpanded))
                enumName = "define_" + key
                enuum = EnumDataType(enumName, 8)
                enuum.add(key, value)
                path = getCategory(getFileName(definitionPath(key)))
                dtMgr.addDataType(enuum, DataTypeConflictHandler.DEFAULT_HANDLER)

        dtMgr.endTransaction(transactionID, True)


def replace(image, currKey, pos):
    replacementString = None
    for key in list(self.defs.keys()):
        if image.find(key) == 0:
            replacementString = self.get(key).image
            break

    return -1


class EnumDataType:
    def __init__(self, name, size):
        pass

    def add(self, value, enumValue):
        pass

    def setCategoryPath(self, path):
        pass


def getCategory(catName):
    if catName is None or len(catName) == 0:
        return CategoryPath.ROOT
    else:
        return CategoryPath(CategoryPath.ROOT, catName)


class CategoryPath:
    ROOT = "root"


# Usage example:

dtMgr = DataTypeManager()
defineTable = DefineTable()

for key in defineTable.getDefineNames():
    if not isArg(key):
        strValue = getValue(key)
        strExpanded = expand(strValue)
        value = long(stripCast(strExpanded))
        enumName = "define_" + key
        enuum = EnumDataType(enumName, 8)
        path = getCategory(getFileName(definitionPath(key)))
        dtMgr.addDataType(enuum, DataTypeConflictHandler.DEFAULT_HANDLER)

dtMgr.endTransaction(transactionID, True)


class PreProcessorConstants:
    NUMERIC = 0
    FP_NUMERIC = 1


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates")
for key in defineTable.getDefineNames():
    if not isArg(key):
        strValue = getValue(key)
        strExpanded = expand(strValue)
        value = long(stripCast(strExpanded))
        enumName = "define_" + key
        enuum = EnumDataType(enumName, 8)
        path = getCategory(getFileName(definitionPath(key)))
        dtMgr.addDataType(enuum, DataTypeConflictHandler.DEFAULT_HANDLER)

dtMgr.endTransaction(transactionID, True)


class AddressEvaluator:
    @staticmethod

    def evaluateToLong(strValue):
        pass


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates")
for key in defineTable.getDefineNames():
    if not isArg(key):
        strValue = getValue(key)
        strExpanded = expand(strValue)
        value = long(stripCast(strExpanded))
        enumName = "define_" + key
        enuum = EnumDataType(enumName, 8)
        path = getCategory(getFileName(definitionPath(key)))
        dtMgr.addDataType(enuum, DataTypeConflictHandler.DEFAULT_HANDLER)

dtMgr.endTransaction(transactionID, True)


class Category:
    pass


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates")
for key in defineTable.getDefineNames():
    if not isArg(key):
        strValue = getValue(key)
        value = long(stripCast(strValue))
        enuum = EnumDataType(enumName, 8)


class CategoryPath:
    pass


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates")
for key in defineTable.getDefineNames():
    if not isArg(key):
        strValue = getValue(key)
        value = long(stripCast(strValue))
        enuum = EnumDataType(enumName, 8)


class CategoryPath:
    pass


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates")
for key in defineTable.getDefineNames():
    if not isArg(key):
        strValue = getValue(key)
        value = long(stripCast(strValue))
        enuum = EnumDataType(enumName,8)


class CategoryPath:
    pass


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates")
for key in defineTable.getDefineNames():
    if not isArg(key):
        strValue = getValue(key)
        value = long(stripCast(strValue = getValue(key)
        enuum = EnumDataType(enumName,8)


class CategoryPath:
    pass


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates"
    pass
        enuum = EnumDataType(enumName,8")


class CategoryPath:
    pass


# Usage example:


class CategoryPath:
    pass


# Usage example:



###



    pass


# Usage example: getValue(key)
        value = long(stripCast(strValue) pass


# Usage example:

transactionID = dtMgr.startTransaction("Add Equates"
    pass
Usage example:

# Usage example:

# Usage

class CategoryPath:
    pass
Usage example:

# Usage example:

# Usage example:

# Usage.

class CategoryPath:

# Usage.
class CategoryPath:

# Usage.

class CategoryPath:

# Usage.

class
Usage

class CategoryPath:

# Usage.
class Path:

# Usage.
class CategoryPath:

# Usage.
class  Usage.
    pass
class CategoryPath:

# Usage.
class
Usage example:

# Usage.
class

Usage
* Usage.
class CategoryPath:

# Usage.
class CategoryPath:

# Usage.

class CategoryPath:

# Usage.
class CategoryPath:

# Usage.
class CategoryPath:

# Usage.
class Path:

# Usage.
class CategoryPath:

    pass
class CategoryPath:

# Usage.
class Path:

# Usage.
class  Usage.
class Path:

# Usage.
class Path:

# Usage.
class
Usage.

class CategoryPath:

* Usage.
class CategoryPath:

# Usage.
class CategoryPath:

Usage.
class CategoryPath:

Usage.
class CategoryPath:

Usage.
class CategoryPath:

    pass
class CategoryPath:

Usage.
class CategoryPath:

Usage.
class CategoryPath:

Usage.

Usage.
class Path:

Usage.
class CategoryPath:

Usage.
class CategoryPath:

Usage.
class CategoryPath:

Usage.
class CategoryPath:

Usage.
class CategoryPath:

Usage.
class
Usage.
class CategoryPath:

Usage.
class
Usage.
class CategoryPath:

Usage.
class Usage.
class CategoryPath:

Usage.

Usage.
class Path:

Usage.
class Usage.
class Usage.
class Path:

Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.

Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.

Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.

Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.

Usage
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.

Usage
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class Usage.
class UsageUsage.
class UsageUsage.



