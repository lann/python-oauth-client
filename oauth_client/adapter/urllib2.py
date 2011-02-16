import urllib2
   
from request import ENTITY_BODY_CONTENT_TYPE
import adapter

class UrllibAdapter(adapter.RequestAdapter):
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
        
    # Client interface

    @classmethod
    def fetch(cls, url, data=None, method='GET', headers={},
              **signing_parameters):
        if method == 'POST':
            if not data:
                raise ValueError(
                    'urllib2 does not support POST without data')
        elif method != 'GET':
            raise ValueError(
                'urllib2 does not support HTTP method %r' % method)
            
        req = UrllibRequest(url, data=data, headers=headers)
        req.oauth_sign(**signing_parameters)
    
        try:
            resp = urllib2.urlopen(req)
        except urllib2.HTTPError, resp:
            pass
        return adapter.Response(resp, resp.code, resp.msg, resp.hdrs)
        
class UrllibRequest(urllib2.Request, adapter.AdapterMixin):
    oauth_adapter_cls = UrllibAdapter
