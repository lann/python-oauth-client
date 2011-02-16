import random
import time
import urlparse

import compat
import util

signature_methods = {}

def register_signature_method(name, cls=None):
    def register(name, cls):
        cls.name = name
        signature_methods[name] = cls
        
    if cls:
        register(name, cls)
        return
    
    def decorator(cls):
        register(name, cls)
        return cls
    return decorator


class SignatureMethod(object):
    def __init__(self, request):
        self.request = request
        
    def get_signature_params(self, oauth_parameters):
        oauth_params = dict(oauth_parameters)
        
        sig_params = dict(
            oauth_signature_method=self.name,
            oauth_nonce=(
                oauth_params.get('oauth_nonce') or self.generate_nonce()),
            oauth_timestamp=(
                oauth_params.get('oauth_timestamp') or '%d' % time.time()),
            )
        
        oauth_params.update(sig_params)
        
        base_string = self.get_signature_base_string(oauth_params)
        
        sig_params.update(
            oauth_signature=self.base_string_signature(base_string))

        return sig_params

    def get_signing_key(self):
        key = [util.oauth_encode(self.request.client.shared_secret), '&']
        if self.request.token:
            key.append(util.oauth_encode(self.request.token.shared_secret))
        return ''.join(key)
            
    def get_signature_base_string(self, oauth_parameters):
        # RFC 5849 3.4.1
        method, uri, http_params = self.request.get_base_string_parts()

        base_string = [method]
        
        # Base String URI (3.4.1.2)
        scheme, host, path, query, _ = urlparse.urlsplit(uri)
        
        scheme = scheme.lower()
        default_port = ':%d' % {'http': 80, 'https': 443}[scheme]

        host = host.lower()
        if host.endswith(default_port):
            host = host[:-len(default_port)]
                        
        base_string.append(urlparse.urlunsplit((scheme, host, path, '', '')))
        
        # Request Parameters (3.4.1.3)
        params = compat.parse_qsl(query)
        
        oauth_params = dict(oauth_parameters)
        oauth_params.pop('realm', None)
        params.extend(oauth_params.items())
                           
        if http_params:
            if hasattr(http_params, 'split'):
                http_params = compat.parse_qsl(
                    http_params, keep_blank_values=True)
            params.extend(http_params)

        encoded_params = sorted(
            (util.oauth_encode(k), util.oauth_encode(v)) for k, v in params)
        
        base_string.append(
            util.oauth_encode('&'.join('%s=%s' % p for p in encoded_params)))

        return '&'.join(base_string)
        
    def base_string_signature(self, base_string):
        raise NotImplementedError('base_string_signature')

    @staticmethod
    def generate_nonce():
        return str(random.randint(1, 2**32))

    
# Signature Methods 
    
import base64
import hmac

@register_signature_method('HMAC-SHA1')
class HmacSha1Signature(SignatureMethod):
    # 3.4.2
    def base_string_signature(self, base_string):
        key = self.get_signing_key()
        digest = hmac.HMAC(key, base_string, compat.sha1).digest()
        return base64.b64encode(digest)
    
@register_signature_method('PLAINTEXT')
class PlaintextSignature(SignatureMethod):
    # 3.4.4
    def get_signature_params(self, oauth_parameters=None):
        params = dict(
            oauth_signature_method=self.name,
            oauth_signature=self.get_signing_key()
            )
        return params
    
