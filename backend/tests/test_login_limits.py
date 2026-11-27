from app.login_limits import bucket_key

def test_bucket_separation():
    assert bucket_key("peer", "example") != bucket_key("account", "example")
    assert bucket_key("account", "example") == bucket_key("account", "example")
    assert len(bucket_key("account", "example")) <= 80
    assert "example" not in bucket_key("account", "example")
