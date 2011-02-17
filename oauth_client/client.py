from adapter import urllib2_oauth
import compat
import util

class Client(object):
    request_token_url = None
    authorize_url = None
    access_token_url = None

    def __init__(self, client, token=None,
                 adapter=urllib2_oauth.Adapter, **fetch_parameters):
        self.adapter = adapter
        self.fetch_parameters = dict(client=client, token=token,
                                     **fetch_parameters)

    def fetch(self, *args, **kwargs):
        raise_errs = kwargs.pop('raise_http_errors', False)
        kwargs = dict(self.fetch_parameters, **kwargs)
        resp = self.adapter.fetch(*args, **kwargs)
        if str(resp.code).startswith('2') or not raise_errs:
            return resp
        else:
            raise ClientError('HTTP error %s: %r' % (resp.code, str(resp)))

    def get_authorize_url(self, authorize_url=None, request_token_url=None,
                          **kwargs):
        """Return a redirect-ready authorize url and temporary credentials"""
        
        url = request_token_url or self.request_token_url
        if not url:
            raise ValueError('request_token_url')
        
        auth_url = authorize_url or self.authorize_url
        if not auth_url:
            raise ValueError('authorize_url')
        
        kwargs.setdefault('method', 'POST')
        if 'oauth_callback' not in self.fetch_parameters:
            kwargs.setdefault('oauth_callback', 'oob')
        
        kwargs.setdefault(raise_http_errors=True)
           
        resp = self.fetch(url, **kwargs)
        
        temp = util.Credentials.build(str(resp))

        auth_url = util.url_extend(
            auth_url, dict(oauth_token=temp.identifier))

        return auth_url, temp

    def get_access_token(self, temporary_credentials, verifier,
                         access_token_url=None, **kwargs):
        
        url = access_token_url or self.access_token_url
        if not url:
            raise ValueError('access_token_url')
            
        if 'oauth_verifier=' in verifier:
            verifier = dict(
                compat.parse_qsl(verifier.split('?')[-1]))['oauth_verifier']
        elif hasattr(verifier, 'get'):
            verifier = verifier.get('oauth_verifier')
        
        kwargs['oauth_verifier'] = verifier
            
        kwargs.setdefault(raise_http_errors=True)
        
        resp = self.fetch(url, **kwargs)
            
        return util.Credentials.build(str(resp))
        
class ClientError(Exception):
    pass
            
        
