import urllib
import urlparse

import signing
import util

OAUTH_VERSION = '1.0'
ENTITY_BODY_CONTENT_TYPE = 'application/x-www-form-urlencoded'

class Request(object):

    def __init__(self, client, token=None, signature_method='HMAC-SHA1',
                 realm=None, **parameters):
        self.client = client
        self.token = token
        self.signature_method = signature_method
        self.realm = realm
        self.parameters = parameters
        
    @property
    def signature_method(self):
        return self._signature_method

    @signature_method.setter
    def signature_method(self, method):
        if not hasattr(method, 'get_signature_params'):
            try:
                method = signing.signature_methods[method]
            except KeyError:
                raise ValueError('Unexpected signature method: %r' % method)
        
        self._signature_method = method
        
    def build_parameters(self, **extra_parameters):
        params = dict(self.parameters, **extra_parameters)
        params.update(('oauth_' % k, params.pop(k))
                      for k in params if not k.startswith('oauth_'))
        
        params.update(oauth_version=OAUTH_VERSION)
        params.update(oauth_consumer_key=self.client.identifier)
        if self.token:
            params.update(oauth_token=self.token.identifier)

        if 'oauth_signature' not in params:
            params.update(
                self.signature_method(self).get_signature_params(params))
         
        return params

    def build_header(self, realm=None, whitespace=' ', **kwargs):
        params = self.build_parameters(**kwargs)
        
        header = ['OAuth realm="%s"' % (realm or self.realm or '')]
        for key, val in params.items():
            header.append('%s="%s"' % (
                    util.oauth_encode(key), util.oauth_encode(val)))
        
        sep = ',' + whitespace
        return sep.join(header)

    def add_oauth_params(self, parameter_method=None, *args, **kwargs):
        if parameter_method:
            add_method = getattr(self, 'add_oauth_%s' % parameter_method, None)
            if add_method:
                add_method(*args, **kwargs)
            else:
                raise NotImplementedError(
                    'parameter_method=%r' % parameter_method)
            
        else:
            exc = NotImplementedError('add_oauth_params')
            
            for method in ['header', 'query', 'body']:
                try:
                    self.add_oauth_params(method, **kwargs)
                    break
                except NotImplementedError:
                    pass
                except Exception, exc:
                    pass
            else:
                raise exc
                
    def add_oauth_header(self):
        raise NotImplementedError('Request.add_oauth_header')
        
    def add_oauth_query(self):
        raise NotImplementedError('Request.add_oauth_query')
    
    def add_oauth_body(self):
        raise NotImplementedError('Request.add_oauth_body')
    
    def get_base_string_parts(self):
        # Return (http_method, http_uri, http_body_params)
        # See 3.4.1.3.1 for info on when to return http_body_params
        raise NotImplementedError('Request.get_base_string_parts')
       
    
class HttpRequest(Request):
    """Dummy/example Request implementation"""
    
    def __init__(self, url, *args, **kwargs):
        self.url = url
        self.method = kwargs.pop('method', 'GET')
        self.body = kwargs.pop('body', None)
        self.headers = kwargs.pop('headers', {})
        
        super(HttpRequest, self).__init__(*args, **kwargs)

    def get_base_string_parts(self):
        return (self.method, self.url, self.body)

    def add_oauth_header(self, **kwargs):
        self.headers['Authorization'] = self.build_header(**kwargs)

    def add_oauth_query(self, **kwargs):
        scheme, host, path, url_qs, frag = urlparse.urlsplit(self.url)

        qs = urllib.urlencode(self.build_parameters(**kwargs))
        if url_qs:
            qs = '%s&%s' % (url_qs, qs)
        
        self.url = urlparse.urlunsplit((scheme, host, path, qs, frag))
        

