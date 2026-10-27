"""A small benign calculator example for PoisonCode Detector testing."""

def calculate(a: float, b: float, operation: str = "add") -> float:
    if operation == "add":
        return a + b
    if operation == "subtract":
        return a - b
    if operation == "multiply":
        return a * b
    if operation == "divide":
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a / b
    raise ValueError(f"Unsupported operation: {operation}")

if __name__ == "__main__":
    print(calculate(12, 4, "divide"))
