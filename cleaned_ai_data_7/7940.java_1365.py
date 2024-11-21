# This class tests a demangler that is derived from MDMang using tests codified in MDMangBaseTest.
class MDemanglerVS2015Test:
    def __init__(self):
        self.test_configuration = MDVS2015TestConfiguration(be_quiet())

def be_quiet():
    # Implement your logic here
    pass

# This class is derived from MDBastTestConfiguration and is allocated below.
class MDVS2015TestConfiguration:
    def __init__(self, quiet):
        # Implement your logic here
        self.quiet = quiet
