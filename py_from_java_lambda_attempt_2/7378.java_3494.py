Here is the translation of the Java code to Python:
```
class Img3TagFactory:
    @staticmethod
    def get(reader):
        tag = str(reader.peek_next_int())
        
        if not tag or len(tag) == 0:  # TODO
            pass
        
        elif tag == "IMG3_TAG_BDID_MAGIC":
            return BdidTag(reader)
        
        elif tag == "IMG3_TAG_BORD_MAGIC":
            return BoardTag(reader)
        
        elif tag == "IMG3_TAG_CERT_MAGIC":
            return CertificateTag(reader)
        
        elif tag == "IMG3_TAG_CHIP_PROD":
            return ChipTag(reader)
        
        elif tag == "IMG3_TAG_DATA_MAGIC":
            return DataTag(reader)
        
        elif tag == "IMG3_TAG_ECID_MAGIC":
            return ExclusiveChipTag(reader)
        
        elif tag == "IMG3_TAG_KBAG_MAGIC":
            return KBagTag(reader)
        
        elif tag == "IMG3_TAG_PROD_MAGIC":
            return ProductionModeTag(reader)
        
        elif tag == "IMG3_TAG_SCEP_MAGIC":
            return ScepTag(reader)
        
        elif tag == "IMG3_TAG_SDOM_MAGIC":
            return SecurityDomainTag(reader)
        
        elif tag == "IMG3_TAG_SEPO_MAGIC":
            return SecurityEpochTag(reader)
        
        elif tag == "IMG3_TAG_SHSH_MAGIC":
            return RsaShaTag(reader)
        
        elif tag == "IMG3_TAG_TYPE_MAGIC":
            return TypeTag(reader)
        
        elif tag == "IMG3_TAG_VERS_MAGIC":
            return VersionTag(reader)
        
        else:
            return UnknownTag(reader)

class BdidTag:
    def __init__(self, reader):
        pass

class BoardTag:
    def __init__(self, reader):
        pass

class CertificateTag:
    def __init__(self, reader):
        pass

class ChipTag:
    def __init__(self, reader):
        pass

class DataTag:
    def __init__(self, reader):
        pass

class ExclusiveChipTag:
    def __init__(self, reader):
        pass

class KBagTag:
    def __init__(self, reader):
        pass

class ProductionModeTag:
    def __init__(self, reader):
        pass

class ScepTag:
    def __init__(self, reader):
        pass

class SecurityDomainTag:
    def __init__(self, reader):
        pass

class SecurityEpochTag:
    def __init__(self, reader):
        pass

class RsaShaTag:
    def __init__(self, reader):
        pass

class TypeTag:
    def __init__(self, reader):
        pass

class VersionTag:
    def __init__(self, reader):
        pass

class UnknownTag:
    def __init__(self, reader):
        pass
```
Note that I did not translate the `StringUtilities` class or any other utility classes from Java to Python.