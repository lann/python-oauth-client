import time
import unittest

import mock

import oauth_client

def build_request(url, client_id, client_secret,
                  token_id=None, token_secret=None, **kwargs):
    from oauth_client.request import HttpRequest as Req
    from oauth_client.util import Credentials as Cred

    if token_id:
        kwargs['token'] = Cred(token_id, token_secret)
    return Req(url, client=Cred(client_id, client_secret), **kwargs)

class TestRequest(unittest.TestCase):
        
    def test_signature_method(self):
        params = build_request('http://test.com', 'x', 'x', signature_method='PLAINTEXT').build_parameters()
        self.assertEqual(params['oauth_signature_method'], 'PLAINTEXT')
        
        params = build_request('http://test.com', 'x', 'x', signature_method='HMAC-SHA1').build_parameters()
        self.assertEqual(params['oauth_signature_method'], 'HMAC-SHA1')
        self.assertTrue('oauth_nonce' in params)
        self.assertTrue('oauth_timestamp' in params)
    
        req = build_request('http://test.com', 'x', 'x')
        req.signature_method = 'PLAINTEXT'
        self.assertEqual(req.signature_method.name, 'PLAINTEXT')

        def fail():
              req.signature_method = '__FAKE__'
        self.assertRaises(ValueError, fail)
        
        class TestMethod(object):
            def __init__(self, _): pass
            def get_signature_params(self, _): return dict(test_param='TEST')
        req.signature_method = TestMethod
        self.assertEqual(req.build_parameters()['test_param'], 'TEST')

        
    def test_params(self):
        
        a,b,c,d = 'abcd'
        
        r = build_request('http://test.com', a, b)
        params = r.build_parameters()
        self.assertEquals(params.get('oauth_version'), '1.0')
        self.assertEquals(params.get('oauth_consumer_key'), a)
        self.assertTrue('oauth_token' not in params)
        self.assertTrue('oauth_signature' in params)
        self.assertTrue('oauth_signature_method' in params)
        
        r = build_request('http://test.com', a, b, c, d)
        params = r.build_parameters()
        self.assertEquals(params.get('oauth_token'), c)

        
class TestUtilityFunctions(unittest.TestCase):
    def test_oauth_encode(self):
        from oauth_client.util import oauth_encode as enc

        for inp, out in [('abcABC123', 'abcABC123'),
                         ('-._~', '-._~'),
                         ('%', '%25'),
                         ('+', '%2B'),
                         ('&=*', '%26%3D%2A'),
                         (u'\u000A', '%0A'),
                         (u'\u0020', '%20'),
                         (u'\u007F', '%7F'),
                         (u'\u0080', '%C2%80'),
                         (u'\u3001', '%E3%80%81'),
                         ]:
            self.assertEqual(enc(inp), out)

    def test_generate_nonce(self):
        from oauth_client.signing import SignatureMethod as SM
        samples = 10
        nonces = set(SM.generate_nonce() for _ in xrange(samples))
        self.assertEqual(len(nonces), samples)
        

class TestSignature(unittest.TestCase):
    def base_string(self, parts, params={}):
        from oauth_client.signing import SignatureMethod as SM
        request = mock.Mock()
        request.get_base_string_parts.return_value = parts
        return SM(request).get_signature_base_string(params)
        
    def request_params(self, *args, **kwargs):
        return build_request(*args, **kwargs).build_parameters()
        
    def test_base_string(self):
        base_string = self.base_string(
            ('GET', 'http://host.com/', None))
        self.assertEqual(base_string, self.base_string(
                ('GET', 'HTTP://HOST.COM:80', None)))
        self.assertNotEqual(base_string, self.base_string(
                ('POST', 'http://host.com/', None)))
        self.assertNotEqual(base_string, self.base_string(
                ('GET', 'http://host.com/', 'x')))
        self.assertNotEqual(base_string, self.base_string(
                ('GET', 'http://host.com:81/', None)))
        
        base_string = self.base_string(
            ('GET', 'https://host.com/path?query=test+string', None))
        self.assertEqual(base_string, self.base_string(
                ('GET', 'https://host.com:443/path?query=test+string', None)))
        self.assertEqual(base_string, self.base_string(
                ('GET', 'https://host.com/path?query=test string', None)))
        self.assertEqual(base_string, self.base_string(
                ('GET', 'https://host.com/path', 'query=test%20string')))
        self.assertEqual(base_string, self.base_string(
                ('GET', 'https://host.com/path', {'query': 'test string'})))
        
        base_string = self.base_string(
            ('GET', 'http://host.com/?x=a&y=2', None))
        self.assertEqual(base_string, self.base_string(
                ('GET', 'http://host.com/?y=2&x=a', None)))
        self.assertEqual(base_string, self.base_string(
                ('GET', 'http://host.com/?y=2', 'x=a')))
        self.assertNotEqual(base_string, self.base_string(
                ('GET', 'http://host.com/?x=a&x=a', None)))
        self.assertNotEqual(base_string, self.base_string(
                ('GET', 'http://host.com/?x=a', 'x=a')))
        self.assertNotEqual(base_string, self.base_string(
                ('GET', 'http://host.com/?X=a&y=2', None)))
        
    @mock.patch('oauth_client.signing.SignatureMethod.generate_nonce')
    @mock.patch('time.time')
    def test_signature(self, time, generate_nonce):
        from oauth_client.request import HttpRequest as Req
        from oauth_client.util import Credentials as Cred
        
        time.return_value = 12345
        generate_nonce.return_value = '54321'
        
        params = self.request_params('http://Example.Com:80/?x=1', 'client_id', 'client_secret')
        self.assertEqual(params['oauth_signature'], 'WF8xKzLkRownUDdNfwYyNXVF1ig=')
        self.assertEqual(params['oauth_signature_method'], 'HMAC-SHA1')

        params = self.request_params('http://Example.Com:80/?x=1', 'client_id', 'client_secret',
                                     'token_id', 'token_secret', signature_method='PLAINTEXT')
        self.assertEqual(params['oauth_signature'], 'client_secret&token_secret')
        self.assertEqual(params['oauth_signature_method'], 'PLAINTEXT')
        
        time.return_value = 12346
        params = self.request_params('http://Example.Com:80/?x=1', 'client_id', 'client_secret',
                                     'token_id', 'token_secret', signature_method='PLAINTEXT')
        self.assertNotEqual(params['oauth_signature'], 'obTE2rPf3MiidXJDPOZ9UwgODvY=')

        time.return_value = 12345
        generate_nonce.return_value = '54322'
        params = self.request_params('http://Example.Com:80/?x=1', 'client_id', 'client_secret',
                                     'token_id', 'token_secret', signature_method='PLAINTEXT')
        self.assertNotEqual(params['oauth_signature'], 'obTE2rPf3MiidXJDPOZ9UwgODvY=')
        
        time.return_value = 1191242096
        generate_nonce.return_value = 'kllo9940pd9333jh'
        params = self.request_params(
            'http://photos.example.net/photos?file=vacation.jpg&size=original',
            'dpf43f3p2l4k3l03', 'kd94hf93k423kf44',
            'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00')
        self.assertEqual(params['oauth_signature'], 'tR3+Ty81lMeYAr/Fid0kMTYa/WM=')
        
       
        
