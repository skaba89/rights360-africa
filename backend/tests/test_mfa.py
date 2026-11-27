import pyotp
from app.mfa import matching_step

def test_valid_totp_and_window():
    secret = pyotp.random_base32()
    now = 1800000000
    totp = pyotp.TOTP(secret)
    assert matching_step(secret,totp.at(now),now) == now//30
    assert matching_step(secret,totp.at(now-30),now) == now//30-1
    assert matching_step(secret,"abcdef",now) is None
    assert matching_step(secret,"1234567",now) is None
