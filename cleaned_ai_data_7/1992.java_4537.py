class GadpVersion:
    VER1 = "gadp1"

def make_request():
    request = {"versions": [VER1]}
    return request

def get_by_name(name):
    if name == VER1:
        return VER1
    else:
        raise ValueError(f"Unknown version: {name}")

print(get_by_name("gadp1"))  # Output: gadp1
