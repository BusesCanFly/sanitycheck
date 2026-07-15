# INERT FIXTURE - a single dynamic-eval, nothing else. Should scan as CAUTION:
# one MED finding, not enough for DANGEROUS. Used to test --strict exit codes.
raise SystemExit("inert fixture")
def handle(expr):
    return eval(expr)   # dyn-exec -> MED -> CAUTION
