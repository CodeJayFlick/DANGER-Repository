Here is the translation of the Java code to Python:

```Python
class ArtFactory:
    def __init__(self):
        pass

    @staticmethod
    def new_art_header(reader) -> 'ArtHeader':
        try:
            magic = reader.read_bytes(0, len(ArtConstants.MAGIC)).decode('utf-8')
            version = reader.read_ascii_string(4, 4)
            if magic == ArtConstants.MAGIC:
                if ArtConstants.is_supported_version(version):
                    switcher = {
                        'kitkat_release': lambda: ArtHeader_KitKat(reader),
                        'lollipop_release': lambda: ArtHeader_Lollipop(reader),
                        'lolipop_mr1_wfc_release': lambda: ArtHeader_LollipopMR1WFC(reader),
                        'marshmallow_release': lambda: ArtHeader_Marshmallow(reader),
                        'nougat_release': lambda: ArtHeader_Nougat(reader),
                        'nougat_mr2_pixel_release': lambda: ArtHeader_NougatMR2Pixel(reader),
                        'oreo_release': lambda: ArtHeader_Oreo(reader),  # v043 and v044 are same format
                        'oreo_dr1_release': lambda: ArtHeader_Oreo(reader),  # v043 and v044 are same format
                        'oreo_mr1_release': lambda: ArtHeader_OreoMR1(reader),
                        'pie_release': lambda: ArtHeader_Pie(reader),
                        'android10_release': lambda: ArtHeader_10(reader),
                        'android11_release': lambda: ArtHeader_11(reader)
                    }
                    return switcher.get(version, lambda: None)()
                else:
                    raise UnsupportedArtVersionException(magic, version)
            else:
                raise IOException("Invalid magic number")
        except Exception as e:
            if isinstance(e, IOException):
                raise
            elif isinstance(e, UnsupportedArtVersionException):
                raise
            else:
                raise


class ArtHeader:
    pass

class ArtConstants:
    MAGIC = b'ART'
    VERSION_KitKat_RELEASE = 'kitkat_release'
    VERSION_LOLLIPOP_RELEASE = 'lollipop_release'
    VERSION_LOLLIPOPMR1_WFC_RELEASE = 'lolipop_mr1_wfc_release'
    VERSION_MARSHMALLOW_RELEASE = 'marshmallow_release'
    VERSION_NOUGAT_RELEASE = 'nougat_release'
    VERSION_NOUGATMR2_PIXEL_RELEASE = 'nougat_mr2_pixel_release'
    VERSION_OREO_RELEASE = 'oreo_release'  # v043 and v044 are same format
    VERSION_OREODR1_RELEASE = 'oreo_dr1_release'  # v043 and v044 are same format
    VERSION_OREAMR1_RELEASE = 'oreo_mr1_release'
    VERSION_PIE_RELEASE = 'pie_release'
    VERSION_ANDROID10_RELEASE = 'android10_release'
    VERSION_ANDROID11_RELEASE = 'android11_release'

class UnsupportedArtVersionException(Exception):
    pass

# Example usage:
reader = BinaryReader()  # implement this class
art_factory = ArtFactory()
try:
    art_header = art_factory.new_art_header(reader)
except Exception as e:
    print(f"Error: {e}")
```

Note that I have not implemented the `BinaryReader` and other classes (`ArtHeader_KitKat`, etc.) in Python, as they seem to be specific to your project. You will need to implement these yourself based on how you are reading binary data in Java.