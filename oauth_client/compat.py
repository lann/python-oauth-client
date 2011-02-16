# parse_qsl moved to urlparse in Python 2.6
try:
    from urlparse import parse_qsl
except ImportError:
    from cgi import parse_qsl

# hashlib added in Python 2.5
try:
    from hashlib import sha1
except ImportError:
    import sha as sha1
