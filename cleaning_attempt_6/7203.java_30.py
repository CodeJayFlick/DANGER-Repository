import io

class OatQuickMethodHeaderFactory:
    @staticmethod
    def get_oat_quick_method_header_size(oat_version):
        if oat_version == "LOLLIPOP_RELEASE":
            return 12 + QuickMethodFrameInfo.SIZE
        elif oat_version in ["LOLLIPOP_MR1_FI_RELEASE", "LOLLIPOP_WEAR_RELEASE", "MARSHMALLOW_RELEASE"]:
            return 16 + QuickMethodFrameInfo.SIZE
        elif oat_version in ["NOUGAT_RELEASE", "NOUGAT_MR1_RELEASE"]:
            return 8 + QuickMethodFrameInfo.SIZE
        elif oat_version in [
                "OREO_RELEASE",
                "OREO_M2_RELEASE",
                "OREO_DR3_RELEASE",
                "PIE_RELEASE"
        ]:
            return 12 + QuickMethodFrameInfo.SIZE
        elif oat_version in ["10_RELEASE", "11_RELEASE"]:
            return 8
        else:
            raise IOError(f"Unsupported OAT version: {oat_version}")

    @staticmethod
    def get_oat_quick_method_header(reader, oat_version):
        if oat_version == "LOLLIPOP_RELEASE":
            return OatQuickMethodHeaderLollipop(reader)
        elif oat_version in ["LOLLIPOP_MR1_FI_RELEASE", "LOLLIPOP_WEAR_RELEASE", "MARSHMALLOW_RELEASE"]:
            return OatQuickMethodHeaderLollipopMR1(reader)
        elif oat_version == "NOUGAT_RELEASE":
            return OatQuickMethodHeaderNougat(reader)
        elif oat_version in [
                "OREO_RELEASE",
                "OREO_M2_RELEASE",
                "OREO_DR3_RELEASE",
                "PIE_RELEASE"
        ]:
            return OatQuickMethodHeaderOreo(reader)
        elif oat_version in ["10_RELEASE", "11_RELEASE"]:
            return OatQuickMethodHeaderAndroid10(reader)
        else:
            raise IOError(f"Unsupported OAT version: {oat_version}")

class QuickMethodFrameInfo:
    SIZE = 0

class OatQuickMethodHeaderLollipop:
    def __init__(self, reader):
        pass

class OatQuickMethodHeaderLollipopMR1:
    def __init__(self, reader):
        pass

class OatQuickMethodHeaderNougat:
    def __init__(self, reader):
        pass

class OatQuickMethodHeaderOreo:
    def __init__(self, reader):
        pass

class OatQuickMethodHeaderAndroid10:
    def __init__(self, reader):
        pass
