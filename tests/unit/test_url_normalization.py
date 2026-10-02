from adi.http.normalization import canonicalize_url, host_of, join_url, path_only


def test_default_port_dropped():
    assert canonicalize_url("http://host:80/") == canonicalize_url("http://host/")


def test_https_default_port_dropped():
    assert canonicalize_url("https://host:443/path") == canonicalize_url("https://host/path")


def test_empty_path_becomes_slash():
    assert canonicalize_url("http://host") == canonicalize_url("http://host/")


def test_fragment_is_dropped():
    assert canonicalize_url("http://host/page#section") == canonicalize_url("http://host/page")


def test_scheme_and_host_lowercased():
    assert canonicalize_url("HTTP://HOST/Path") == "http://host/Path"


def test_query_param_order_is_normalized():
    a = canonicalize_url("http://host/search?b=2&a=1")
    b = canonicalize_url("http://host/search?a=1&b=2")
    assert a == b


def test_semantically_different_queries_never_collapse():
    a = canonicalize_url("http://host/item?id=1")
    b = canonicalize_url("http://host/item?id=2")
    assert a != b


def test_non_default_port_preserved():
    a = canonicalize_url("http://host:8080/")
    b = canonicalize_url("http://host/")
    assert a != b


def test_path_only_strips_query_and_scheme():
    assert path_only("http://host:8080/api/orders?id=1") == "/api/orders"


def test_host_of():
    assert host_of("https://example.com:8443/x") == "example.com"


def test_join_url_resolves_relative_links():
    assert join_url("http://host/dir/page", "../other") == canonicalize_url("http://host/other")
    assert join_url("http://host/page", "/absolute") == canonicalize_url("http://host/absolute")
