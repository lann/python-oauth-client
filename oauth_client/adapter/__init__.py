from oauth_client import request

class RequestAdapter(request.Request):
    """Provide OAuth functionality to a wrapped HTTP request object"""

    METHOD_ATTR = None
    URL_ATTR = None
    
    adapted_cls = None
    
    def __init__(self, wrapped, *args, **kwargs):
        self.wrapped = wrapped
        super(RequestAdapter, self).__init__(*args, **kwargs)
    
    # Signing interface
        
    def get_base_string_parts(self):
        """Get base string parts as a list: [method, url, body]

        For each of the parts, provide either:

        - A method get_request_<part> that returns the value 

        - A string <PART>_ATTR naming an (optionally callable)
          attribute of self.wrapped 

        """
          
        parts = []
        for part in ['method', 'url', 'body']:
            method = getattr(self, 'get_request_%s' % part, None)
            attr_name = getattr(self, '%s_ATTR' % part.upper(), None)
            if method:
                val = method()
            elif attr_name:
                val = getattr(self.wrapped, attr_name)
                if callable(val):
                    val = val()
            else:
                raise NotImplementedError('get_base_string_parts [%r]' % part)

            parts.append(val)
        return parts
    
    # Client interface

    @classmethod
    def fetch(cls, url, data=None, method='GET', headers={},
              **signing_parameters):
        """Return a Response object for request and signing parameters"""
        
        raise NotImplementedError('fetch')
        
class Response(object):
    def __init__(self, content, code=None, headers=None):
        self.content = content
        self.code = int(code or 200)
        self.headers = headers or {}

    def __str__(self):
        if hasattr(self.content, 'read'):
            return self.content.read()
        else:
            return str(self.content)
            
class AdapterMixin(object):
    """Mixin for HTTP request objects that provides request.oauth_sign()"""

    oauth_adapter_cls = None # RequestAdapter

    def oauth_sign(self, *args, **kwargs):
        parameter_method = kwargs.pop('parameter_method', None)
        wrapper = self.oauth_adapter_cls(self, *args, **kwargs)
        wrapper.add_oauth_params(parameter_method)
        return wrapper
