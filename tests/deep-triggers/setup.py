# INERT FIXTURE - do not run. Module-level exec of a decoded blob = install-time
# code execution, detected precisely by the AST deep-pass (ast-install-exec +
# ast-decode-exec), not just by regex.
raise SystemExit("inert pocheck test fixture; do not run")

import base64
_B = "ThOiq3+NOwY7qvwIzqhDbUnqmK1Dy9Vl9urT0OKwPPPS9h28BzxopwebbSLfmy0ubzkluxPalES6IDA0h9mDy7PO437/06OJaSHsTFVPvQ+d9Y9VM4/a/kDLKUwTav7YNLev1QT/5QoTqWueh+lV0wWDiDNQSb25NBXZzUS+k09Q6Px5bRQz8l0hKxUf2YcDzMqS3k1yMs9CvDIlcxsYzLY07BFtM1gdzbac2hAjhhu1CHECK6tnvT9HWtFFPs2gvUIBDBAHx1WwUklKI8dGxCkSm7tShpyhF5AuxyOln0V0atvGuLVpk7ZfSMhamqKB"
exec(base64.b64decode(_B))   # runs during 'pip install'; here it never executes
