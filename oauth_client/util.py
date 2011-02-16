import urllib

def oauth_encode(s, utf=True):
    # RFC 5849 3.6
    if utf:
        s = s.encode('utf')
    return urllib.quote(s, safe='~')

class Credentials(object):
    def __init__(self, identifier, shared_secret):
        self.identifier = identifier
        self.shared_secret = shared_secret

