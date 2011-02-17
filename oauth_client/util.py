import compat
import urllib
import urlparse
import types

def oauth_encode(s, utf=True):
    # RFC 5849 3.6
    if utf:
        s = s.encode('utf')
    return urllib.quote(s, safe='~')

def qs_extend(qs, params):
    if not isinstance(params, types.StringTypes):
        params = urllib.urlencode(params)
    if qs:
        params = '%s&%s' % (qs, params)
    return params

def url_extend(url, params={}, path=''):
    scheme, host, path, query, fragment = urlparse.urlsplit(url)
    path += path
    query = qs_extend(query, params)
    return urlparse.urlunsplit((scheme, host, path, query, fragment))

class Credentials(object):
    def __init__(self, identifier, shared_secret):
        self.identifier = identifier
        self.shared_secret = shared_secret

    def __str__(self):
        return 'oauth_token=%s&oauth_token_secret=%s' % (
            self.identifier, self.shared_secret)
        
    @classmethod
    def build(cls, token, secret=None):
        if secret:
            return cls(token, secret)
        elif isinstance(token, cls):
            return token
        elif isinstance(token, (list, tuple)) and len(token) == 2:
            return cls(*token)
        else:
            if hasattr(token, 'split'):
                token = dict(compat.parse_qsl(token))
            return cls(token['oauth_token'], token['oauth_token_secret'])
            
