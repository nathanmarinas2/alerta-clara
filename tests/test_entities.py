from app.entities import registrable_domain


def test_registrable_domain_uses_public_suffix_boundaries() -> None:
    assert registrable_domain("https://login.example.co.uk/access") == "example.co.uk"
    assert registrable_domain("https://sub.example.com/path") == "example.com"
    assert registrable_domain("https://192.0.2.10/path") == "192.0.2.10"
