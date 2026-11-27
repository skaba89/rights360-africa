from app.recovery import code_hash, normalize, consume_recovery

def test_normalization():
    code = "01234567-89abcdef-01234567-89abcdef"
    assert normalize(code) == "0123456789ABCDEF0123456789ABCDEF"
    assert code_hash(code) == code_hash(normalize(code))
    assert len(code_hash(code)) == 64

def test_invalid_code_never_queries_database():
    for code in (None, "", "wrong", "é"*32):
        assert consume_recovery(None, None, code) is False
