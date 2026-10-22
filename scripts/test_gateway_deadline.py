import json
import unittest
from unittest.mock import patch

class DeadlineChecks(unittest.TestCase):
    def test_task_budget_bounds_shared_wait(self):
        from utils.gateway_client import transport
        class Response:
            def __init__(self,code,data):self.status_code=code;self.data=data
            def iter_content(self,**kw):yield json.dumps(self.data).encode()
            def close(self):pass
            def __enter__(self):return self
            def __exit__(self,*a):pass
        class Client:
            headers={}
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def post(self,url,**kw):return Response(202,{'data':{'id':'a'*24}})
            def get(self,url,**kw):return Response(200,{'data':{'status':'queued'}})
        ticks=[0]
        def clock():ticks[0]+=0.2;return ticks[0]
        settings={'timeout':5,'gateway_wait':90,'gateway_url':'http://127.0.0.1:1','client_token':'x'*48,'context_length':1024,'think':False}
        with patch('utils.gateway_client.requests.Session',Client),patch('utils.gateway_client.time.monotonic',clock),patch('utils.gateway_client.time.sleep'):
            with self.assertRaises(TimeoutError):transport(settings,[],{},dict(request_id='r',task='active_plan',gateway_wait=1))
        self.assertLess(ticks[0],3,'shared default wait must not override investigation remaining budget')

if __name__=='__main__':unittest.main()
