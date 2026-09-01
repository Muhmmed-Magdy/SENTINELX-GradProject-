import requests
base='http://127.0.0.1:8001'
s=requests.Session()
r=s.post(base+'/api/auth/login', json={'email':'admin@soc.local','password':'admin123'})
print('login', r.status_code, r.text)
if not r.ok:
    raise SystemExit()
# Support both possible token key names returned by auth endpoint
token = r.json().get('access_token') or r.json().get('token')
headers={'Authorization':f'Bearer {token}'}
print('calling /api/ai/status')
sresp=s.get(base+'/api/ai/status', headers=headers)
print('/api/ai/status', sresp.status_code, sresp.text)
print('calling /api/ai/chat')
cresp=s.post(base+'/api/ai/chat', headers=headers, json={'message':'Please respond briefly: is AI live?'})
print('/api/ai/chat', cresp.status_code, cresp.text)
