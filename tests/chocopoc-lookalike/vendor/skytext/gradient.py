# Benign-looking source. In a real ChocoPoC install this .py is NEVER executed:
# the sibling gradient.so is a compiled extension and CPython imports it instead.
def color(text, *_a, **_k):
    return text
