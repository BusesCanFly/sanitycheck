# INERT FIXTURE. A long, high-entropy base64 literal sitting next to a decoder is
# the shape of an embedded payload. The deep-pass scores it by Shannon entropy so
# ordinary long strings do not false-positive.
raise SystemExit("inert pocheck test fixture; do not run")
import base64
PAYLOAD = "ThOiq3+NOwY7qvwIzqhDbUnqmK1Dy9Vl9urT0OKwPPPS9h28BzxopwebbSLfmy0ubzkluxPalES6IDA0h9mDy7PO437/06OJaSHsTFVPvQ+d9Y9VM4/a/kDLKUwTav7YNLev1QT/5QoTqWueh+lV0wWDiDNQSb25NBXZzUS+k09Q6Px5bRQz8l0hKxUf2YcDzMqS3k1yMs9CvDIlcxsYzLY07BFtM1gdzbac2hAjhhu1CHECK6tnvT9HWtFFPs2gvUIBDBAHx1WwUklKI8dGxCkSm7tShpyhF5AuxyOln0V0atvGuLVpk7ZfSMhamqKB"
_ = base64.b64decode(PAYLOAD)
