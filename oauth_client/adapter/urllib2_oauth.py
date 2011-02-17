import urllib2
   
from oauth_client import adapter
from oauth_client import util
from oauth_client.request import ENTITY_BODY_CONTENT_TYPE

class Adapter(adapter.RequestAdapter):
    # Signing interface
    
    METHOD_ATTR = 'get_method'
    URL_ATTR = 'get_full_url'

    def get_request_body(self):
        req = self.wrapped
        content_type = req.get_header(
            'Content-Type', ENTITY_BODY_CONTENT_TYPE)
        if req.data and content_type == ENTITY_BODY_CONTENT_TYPE:
            return req.data
        else:
            return None

    # Parameter method interface
        
    def add_oauth_header(self, **kwargs):
        value = self.build_header(**kwargs)
        self.wrapped.add_header('Authorization', value)
        
    def add_oauth_body(self, **kwargs):
        body = self.get_request_body()
        if self.wrapped.data and body is None:
            raise ValueError('cannot add oauth body; already has unknown data')
        self.wrapped.add_data(
            util.qs_extend(body, self.build_parameters(**kwargs)))
        
    # Client interface

    @classmethod
    def fetch(cls, url, data=None, method='GET', headers={},
              **signing_parameters):
        if method == 'POST' and not data:
            param_method = signing_parameters.setdefault(
                'parameter_method', 'body')
            
            if param_method != 'body':
                raise ValueError('cannot POST with data=None and '
                                 'parameter_method=%r' % param_method)
            
        elif method not in ['GET', 'POST']:
            raise ValueError(
                'urllib2 does not support HTTP method %r' % method)
            
        req = Request(url, data=data, headers=headers)
        req.oauth_sign(**signing_parameters)
    
        try:
            resp = urllib2.urlopen(req)
        except urllib2.HTTPError, resp:
            pass
        return adapter.Response(resp, resp.code, resp.headers)
        
class Request(urllib2.Request, adapter.AdapterMixin):
    oauth_adapter_cls = Adapter
