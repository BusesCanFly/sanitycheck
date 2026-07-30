# INERT FIXTURE - one MED finding and nothing else, so it scans as CAUTION
# rather than DANGEROUS. Used to test the CAUTION verdict and --strict exit code.
# Reading cloud credentials is worth a look but is not on its own proof of
# anything, which is exactly what MED means.
raise SystemExit("inert fixture")
import os

def load_profile():
    path = os.path.expanduser("~/.aws/credentials")   # secret-scrape -> MED -> CAUTION
    with open(path) as fh:
        return fh.read()
