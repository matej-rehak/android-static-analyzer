import apkscan


# Balíček jde importovat a má nastavenou verzi.
def test_version():
    assert apkscan.__version__
