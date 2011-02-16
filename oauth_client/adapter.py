import request

def _attr_getter(part):
    def getter(self, request):
        attr_name = getattr(self, '%s_ATTR' % part.upper(), None)
        if attr_name:
            attr = getattr(request, attr_name)
            if callable(attr):
                attr = attr()
            return attr
        else:
            raise NotImplementedError('get_%s' % part)
    return getter
            
class RequestAdapter(request.Request):
    METHOD_ATTR = None
    URL_ATTR = None
    
    def __init__(self, request, *args, **kwargs):
        self._request = request
        super(RequestAdapter, self).__init__(*args, **kwargs)
        
    def get_base_string_parts(self):
        parts = []
        for part in ['method', 'url', 'body']:
            parts.append(
                getattr(self, 'get_request_%s' % part)(self._request))
        return parts
                
    get_request_method = _attr_getter('method')
    get_request_url = _attr_getter('url')
    get_request_body = _attr_getter('body')

    def add_oauth_params(self, parameter_method=None, *args, **kwargs):
        super(RequestAdapter, self).add_oauth_params(
            parameter_method, self._request, *args, **kwargs)
    

class AdapterMixin(object):
    oauth_adapter_cls = None

    def oauth_request(self, *args, **kwargs):
        return self.oauth_adapter_cls(self, *args, **kwargs)
        
    def oauth_sign(self, *args, **kwargs):
        parameter_method = kwargs.pop('parameter_method', None)
        self.oauth_request(*args, **kwargs).add_oauth_params(parameter_method)
        
    
import urllib2
    
class UrllibAdapter(RequestAdapter):
    METHOD_ATTR = 'get_method'
    URL_ATTR = 'get_full_url'

    def get_request_body(self, req):
        content_type = req.get_header(
            'Content-Type', request.ENTITY_BODY_CONTENT_TYPE)
        if req.data and content_type == request.ENTITY_BODY_CONTENT_TYPE:
            return req.data
        else:
            return None

    def add_oauth_header(self, req, **kwargs):
        value = self.build_header(**kwargs)
        req.add_header('Authorization', value)
        
        
class UrllibRequest(urllib2.Request, AdapterMixin):
    oauth_adapter_cls = UrllibAdapter
