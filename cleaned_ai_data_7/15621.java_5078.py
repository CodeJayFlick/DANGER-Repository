class VersionRange:
    ANY = None  # or you can use a special value like -1 for example

    def __init__(self, recommended_version=None, restrictions=[]):
        self.recommended_version = recommended_version
        self.restrictions = restrictions

    @property
    def get_recommended_version(self):
        return self.recommended_version

    @property
    def get_restrictions(self):
        return self.restrictions


def parse(spec: str) -> 'VersionRange':
    if not spec or not spec.strip():
        return VersionRange()

    restrictions = []
    process = spec
    version = None
    upper_bound = None
    lower_bound = None

    while True:
        start_index1 = process.find(')')
        start_index2 = process.find(']')

        index = start_index2 if start_index2 >= 0 else (start_index1 if start_index1 >= 0 else -1)

        restriction = parse_restriction(process[:index + 1])
        if lower_bound is None:
            lower_bound = restriction.lower_bound
        elif upper_bound and restriction.lower_bound < upper_bound:
            raise ValueError(f"Ranges overlap: {spec}")

        restrictions.append(restriction)
        upper_bound = restriction.upper_bound

        process = process[index + 1:].strip()

        if process and process[0] == ',':
            process = process[1:].strip()
        else:
            break

    if process:
        version = Version(process.strip())
        restrictions.append(Restriction.EVERYTHING)
    return VersionRange(version, restrictions)


def parse_restriction(spec: str) -> 'Restriction':
    lower_bound_inclusive = spec.startswith('[')
    upper_bound_inclusive = spec.endswith(']')

    process = spec[1:-1].strip()

    restriction = None

    if ',' not in process:
        version = Version(process.strip())
        restriction = Restriction(version, True, version, True)
    else:
        lower_bound, upper_bound = process.split(',')
        lower_version = Version(lower_bound.strip()) if lower_bound else None
        upper_version = Version(upper_bound.strip()) if upper_bound else None

        if not (lower_version and upper_version) or upper_version < lower_version:
            raise ValueError(f"Range defies version ordering: {spec}")

        restriction = Restriction(lower_version, lower_bound_inclusive,
                                   upper_version, upper_bound_inclusive)

    return restriction


def matches(self, artifacts):
    return [artifact for artifact in artifacts if self.contains(artifact.get_parsed_version())]


def contains(self, version):
    if VersionRange.ANY == self:
        return True
    elif self.recommended_version is not None:
        return self.recommended_version == version

    for restriction in self.restrictions:
        if restriction.contains(version):
            return True

    return False


class Artifact:
    def __init__(self, name: str, version: 'Version'):
        self.name = name
        self.version = version

    @property
    def get_version(self):
        return self.version

    @property
    def get_parsed_version(self) -> 'Version':
        # implement this method based on your actual implementation


class Version:
    def __init__(self, spec: str):
        self.spec = spec

    @property
    def to_string(self):
        return self.spec


class Restriction:
    EVERYTHING = None  # or you can use a special value like -1 for example

    def __init__(self, lower_bound=None, lower_inclusive=True,
                 upper_bound=None, upper_inclusive=True):
        self.lower_bound = lower_bound
        self.lower_inclusive = lower_inclusive
        self.upper_bound = upper_bound
        self.upper_inclusive = upper_inclusive

    @property
    def contains(self, version: 'Version'):
        if not self.lower_bound and not self.upper_bound:
            return True  # or you can implement your own logic here


class Restriction(Restriction):
    pass


# Example usage:

version_range = VersionRange.parse("1.0,[2.0,),3.0]")
print(version_range.get_recommended_version)  # prints: None
print(version_range.get_restrictions)  # prints: [Restriction(lower_bound=Version('2.0'), lower_inclusive=True, upper_bound=Version('), upper_inclusive=False)]

artifact = Artifact("my-artifact", Version("1.0"))
if version_range.contains(artifact):
    print(f"{artifact.name} matches the version range")
else:
    print(f"{artifact.name} does not match the version range")

print(version_range.matches([Artifact("a", Version("2.0")), Artifact("b", Version("3.0"))]))
