# Functions that are tested
def add(a, b):
    """Returns the sum of two numbers."""
    return a + b

def subtract(a, b):
    """Returns the difference of two numbers."""
    return a - b


'''
TESTS HERE
'''
def test_add_positive_numbers():
    # Pytest uses the standard Python 'assert' keyword
    assert add(5, 7) == 12
    
def test_add_negative_numbers():
    assert add(-1, -5) == -6

def test_subtract_positive():
    assert subtract(10, 4) == 6
    
def test_subtract_zero():
    assert subtract(5, 0) == 5