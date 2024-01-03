class os_version:
    def __init__(self, version):
        ver = version.split(".")
        self.version_str = version
        self.major, self.minor = int(ver[0]), int(ver[1])

    def __repr__(self):
        return self.version_str

    def __str__(self):
        return self.version_str

    def __lt__(self, other):
        other_version = os_version.to_version(other)
        if (other_version == None):
            return False
        return (self.major < other_version.major) or ((self.major == other_version.major) and (self.minor < other_version.minor))
    
    def __eq__(self, other):
        other_version = os_version.to_version(other)
        if (other_version == None):
            return False
        return (self.major == other_version.major) and (self.minor == other_version.minor)

    def __le__(self, other):
        return (self < other) or (self == other)

    def __gt__(self, other):
        return not (self <= other)

    def __ge__(self, other):
        return not (self < other)

    @staticmethod
    def to_version(obj):
        if isinstance(obj, str):
            return os_version(obj)
        if isinstance(obj, float):
            return os_version(str(obj))
        if isinstance(obj, os_version):
            return obj
        return None