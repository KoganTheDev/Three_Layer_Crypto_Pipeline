

#  TDD with Pytest: A Modern Workflow

This guide outlines the best practices for implementing the **Test-Driven Development (TDD)** workflow using the simple, yet powerful, **`pytest`** framework in Python.

TDD involves three main steps—**Red, Green, Refactor**—which ensure your code is stable, well-tested, and easy to maintain.

-----

## 1\.  RED: Write a Failing Test

The first step in TDD is to write a test for a feature that doesn't exist yet. This forces you to clearly define the required behavior **before** you write any implementation code.

###  Action Steps

1.  **Define the Test File:** Create a test file (e.g., `test_feature.py`) in your dedicated `tests/` directory.
2.  **Write the Assertion:** Write a simple `def test_...():` function that calls your future function with specific inputs and asserts the expected output using the standard Python `assert` keyword.

### Example (`test_calculator.py`)

Imagine we want to write a function `add(a, b)`.

```python
# test_calculator.py

# 1. Write the test for the desired behavior.
def test_add_positive_numbers():
    # We expect 5 + 7 to equal 12
    # NOTE: The 'add' function does not exist yet!
    assert add(5, 7) == 12

# 2. Run the test and confirm it FAILS (Red).
# Run in terminal: pytest
```

When you run `pytest`, it will fail with an error like `NameError: name 'add' is not defined`. This is the **Red** stage.

-----

## 2\. GREEN: Write Minimum Viable Code

The goal here is simple: write the **minimum amount of code** required to make the failing test pass. Do not worry about edge cases, efficiency, or elegant structure yet.

### 📝 Action Steps

1.  **Create the Source File:** Create the source file (e.g., `calculator.py`) and define the function you just tested.
2.  **Implement Only for the Test:** Write the code to satisfy the one failing test case.

### Example (`calculator.py`)

```python
# calculator.py

def add(a, b):
    # This minimal implementation is enough to pass the 'Red' test.
    return a + b 
```

Now, run the test again:

```bash
# Run in terminal: pytest
```

The test should now **PASS (Green)**. If it passes, you know your basic requirement is met.

-----

## 3\. REFACTOR: Improve the Code and Tests

With your test passing (Green), you now have the confidence to safely clean up and improve your code without fear of breaking existing functionality. The tests act as a safety net.

### 📝 Action Steps

1.  **Refactor the Source Code:** Simplify logic, improve variable names, or optimize the algorithm.
2.  **Refactor the Tests (Optional but Recommended):** Improve test readability and efficiency, often by **parameterizing** them.

### Example: Refactoring Tests with Parameterization

To avoid writing multiple `test_add_...` functions, use `pytest.mark.parametrize` to easily add new test cases, which is highly recommended for easy maintenance.

```python
# test_calculator.py (Refactored)
import pytest

# Define a list of test cases: (a, b, expected_result)
@pytest.mark.parametrize("a, b, expected", [
    (5, 7, 12),       # Positive numbers
    (-1, -5, -6),     # Negative numbers
    (100, 0, 100),    # Identity case
])
def test_add_cases(a, b, expected):
    """Tests the add function with various inputs."""
    assert add(a, b) == expected
```

This is the **Green** stage, and you're ready to start the cycle over for the next feature (e.g., implementing `subtract`).

-----

##  Running Your Tests

### Prerequisites

You only need `pytest` installed:

```bash
pip install pytest
```

### Command

Run `pytest` from the root directory of your project:

```bash
# Finds and runs all tests in files named test_*.py or *_test.py
pytest 
```