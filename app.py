"""Dedicated origin for DEVICE enrollment and cross-service bootstrapping.
No user authentication or board data served here. No arbitrary redirect targets.
"""
import os,hashlib,secrets
from urllib.parse import urlencode
from flask import Flask,request,jsonify,make_response,redirect,render_template_string
import psycopg
from psycopg.rows import dict_row
app=Flask(__name__)
COOKIE='__Host-device_primary'
AGE=90*24*3600

def db():
    return psycopg.connect(host='/cloudsql/'+os.environ['INSTANCE_CONNECTION_NAME'],
        dbname=os.getenv('AUTH_DB_NAME','operations'),user=os.environ['AUTH_DB_USER'],
        password=os.environ['AUTH_DB_PASSWORD'],row_factory=dict_row)
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def same_origin():
    origin=request.headers.get('Origin','')
    return origin=='https://'+request.host
@app.after_request
def headers(r):
    r.headers['Cache-Control']='no-store';r.headers['Referrer-Policy']='no-referrer'
    r.headers['X-Content-Type-Options']='nosniff'
    r.headers['Content-Security-Policy']="default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    return r
@app.get('/health')
def health():return jsonify(ok=True)
@app.get('/device/enrol')
def page():
    return render_template_string('<!doctype html><html><meta name="viewport" content="width=device-width, initial-scale=1"><title>Register kiosk</title><style>body{font:16px system-ui;background:#f1f5f9;display:grid;place-items:center;min-height:90vh}main{padding:28px;background:white;border-radius:10px;max-width:440px}input,button{font:inherit;padding:12px;width:100%;box-sizing:border-box;margin:10px 0}button{background:#173d65;color:white;border:0}</style><main><h2>Kiosk enrolment</h2><p>Enter the single-use code issued by Security Administration.</p><input id="code" type="password" autocomplete="off"><button id="submit">Enrol device</button><p id="msg" role="status"></p><script>document.getElementById(\'submit\').onclick=async()=>{try{let r=await fetch(\'/device/enrol\',{method:\'POST\',credentials:\'same-origin\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({code:document.getElementById(\'code\').value})});let j=await r.json();if(!r.ok)throw Error(j.error||\'Enrolment failed\');document.getElementById(\'msg\').textContent=\'Enrolled. Open an authorised board tab.\';}catch(e){document.getElementById(\'msg\').textContent=e.message}}</script></main></html>')
@app.post('/device/enrol')
def enrol():
    if not same_origin():return jsonify(error='Origin rejected'),403
    p=request.get_json(silent=True) or {};code=p.get('code')
    if not isinstance(code,str) or not(35<=len(code)<=128):return jsonify(error='Invalid code'),403
    secret=secrets.token_urlsafe(48)
    try:
        with db() as c:
            row=c.execute('SELECT public.auth_device_redeem_enrolment(%s,%s) AS id',(digest(code),digest(secret))).fetchone()
            if not row or row['id'] is None:return jsonify(error='Invalid or expired code'),403
            c.commit()
    except Exception:
        app.logger.exception('Device enrollment failed');return jsonify(error='Enrollment unavailable'),503
    r=make_response(jsonify(ok=True));r.set_cookie(COOKIE,secret,secure=True,httponly=True,samesite='Lax',max_age=AGE,path='/');return r
@app.get('/device/start/<service_code>')
def start(service_code):
    cred=request.cookies.get(COOKIE,'')
    if not(40<=len(cred)<=256):return redirect('/device/enrol')
    ticket=secrets.token_urlsafe(32)
    try:
        with db() as c:
            svc=c.execute('SELECT return_url FROM public.auth_device_services WHERE service_code=%s AND is_active',(service_code,)).fetchone()
            if not svc:return jsonify(error='Unknown service'),404
            ok=c.execute('SELECT public.auth_device_issue_ticket(%s,%s,%s) AS ok',(digest(cred),service_code,digest(ticket))).fetchone()['ok']
            if not ok:return jsonify(error='Kiosk not authorised or expired'),403
            c.commit()
    except Exception:
        app.logger.exception('Device ticket issue failed');return jsonify(error='Auth service unavailable'),503
    # Target URL is trusted DB configuration, never caller-controlled.
    target=svc['return_url']+('?'+urlencode({'ticket':ticket}) )
    return redirect(target,302)

