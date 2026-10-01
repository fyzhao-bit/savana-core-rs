"""Opt-in software authenticator for disposable synthetic experiments ONLY.

This emulates WebAuthn UP/UV flags: it is NOT evidence of a human, hardware, or
production authentication. Real enrollment, challenge/signature verification,
root authorization, execution and release checks still run in the native SDK.
Never import this module into production entry points or expose it to a model.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .agentdojo_provider import canonical
from .protected_operator import private_read, retain

MODE = 'benchmark_software_identity_v1'
DIRECTORY = Path('/var/lib/savana-experiment-auth/software-benchmark')
PROFILE = DIRECTORY / 'profile.json'
PUBLIC_PROFILE = Path('/etc/savana/benchmark-preauthorization.json')
ORIGIN = 'http://localhost:8766'


def require_disposable_host():
    import subprocess
    import sys
    if sys.platform!='linux' or os.geteuid()!=0:
        raise ValueError('disposable_linux_root_required')
    marker=Path('/run/savana-file-backed-disposable').lstat()
    if not stat.S_ISREG(marker.st_mode) or marker.st_uid!=0 or marker.st_mode&0o077:
        raise ValueError('explicit_disposable_marker_required')
    subprocess.run(['systemctl','is-active','--quiet','savana-acceptance-expiry.timer'],
        check=True,capture_output=True,timeout=5)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def unb64(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('invalid_test_binary')
    raw = base64.urlsafe_b64decode(value+'='*(-len(value)%4))
    if b64(raw) != value: raise ValueError('noncanonical_test_binary')
    return raw


def strict_json(value):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result: raise ValueError('duplicate_field')
            result[k] = v
        return result
    return json.loads(value, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))


def catalog_digest():
    """Every reviewed contract the finite pre-consent may approve, plus the fixed
    review rules a planner-drafted program must pass to be approved."""
    from .agentdojo_tasks import reviewed_contracts
    from .drafted_tasks import review_policy
    return hashlib.sha256(canonical([*(t.document() for t in reviewed_contracts()),
                                     review_policy()])).hexdigest()


def validate_profile(p, *, now_ms=None):
    """Validate public labels/bindings; offline audits need not be unexpired."""
    if (type(p) is not dict or set(p)!={'schema','mode','principal','installation','catalog_digest',
            'batch_id','expires_at_unix_ms','human_verification','hardware_attestation','production_acceptance'}
        or type(p['schema']) is not int or p['schema']!=1 or p['mode']!=MODE or p['catalog_digest']!=catalog_digest()
        or any(p[k] is not False for k in ('human_verification','hardware_attestation','production_acceptance'))
        or any(type(p[k]) is not str or not re.fullmatch('[0-9a-f]{64}',p[k]) or p[k]=='0'*64
               for k in ('principal','installation','batch_id'))
        or type(p['expires_at_unix_ms']) is not int or p['expires_at_unix_ms']<=0
        or (now_ms is not None and not now_ms<p['expires_at_unix_ms']<=now_ms+1800000)):
        raise ValueError('invalid_benchmark_profile')
    return p


def load_profile(path=PUBLIC_PROFILE):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        m=os.fstat(fd)
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022 or m.st_size>4096:
            raise ValueError('root_benchmark_profile_required')
        p=strict_json(os.read(fd,4097))
    finally: os.close(fd)
    return validate_profile(p,now_ms=time.time_ns()//1000000)


class SoftwareCeremonyQueue:
    """Only an explicitly armed disposable batch can use this root-held key."""
    def __init__(self):
        require_disposable_host()
        self.profile=load_profile()
        registered=strict_json(private_read(PROFILE,4096))
        if registered['mode']!=MODE or registered['principal']!=self.profile['principal']:
            raise ValueError('benchmark_identity_binding')
        self.identity=SoftwareIdentity(DIRECTORY)
        self.active=False;self.bootstraps=0

    def poll(self): return None
    def complete(self, _): raise ValueError('benchmark_is_not_browser_authentication')

    def bootstrap(self, issue):
        self._live()
        if self.bootstraps>=9: raise ValueError('benchmark_case_limit')
        self.bootstraps+=1
        return issue()

    def _live(self):
        if not self.active or time.time_ns()//1000000>=self.profile['expires_at_unix_ms']:
            raise ValueError('benchmark_batch_not_live')

    def exchange(self, request, timeout=115):
        if type(request) is not dict or type(request.get('protocol_version')) is not int:
            raise ValueError('benchmark_request_type')
        if request.get('type')=='experiment.ready':
            expected=hashlib.sha256(canonical(self.profile)).hexdigest()
            if (set(request)!={'protocol_version','type','launch_id','benchmark_profile_sha256'}
                or request['benchmark_profile_sha256']!=expected or request['protocol_version']!=1
                or self.active or type(request['launch_id']) is not str
                or not re.fullmatch('[A-Za-z0-9_-]{43}',request['launch_id'])
                or time.time_ns()//1000000>=self.profile['expires_at_unix_ms']):
                raise ValueError('benchmark_start_request')
            marker=DIRECTORY/('launched-'+self.profile['batch_id']+'.json')
            if marker.exists(): raise ValueError('benchmark_already_started')
            retain(marker,canonical(dict(batch=self.profile['batch_id'],launch=request['launch_id'])))
            self.active=True;self._live()
            return dict(protocol_version=1,type='experiment.start',launch_id=request['launch_id'],start=True,
                benchmark_profile_sha256=expected)
        self._live()
        if (set(request)!={'protocol_version','type','options_json'} or request['protocol_version']!=1
            or request['type']!='webauthn.assert' or not self.bootstraps):
            raise ValueError('benchmark_does_not_approve_arbitrary_requests')
        response=self.identity.assert_credential(unb64(request['options_json']))
        return dict(protocol_version=1,type='webauthn.assertion',**{k:b64(v) for k,v in response.items()})


def cbor(value):
    """Tiny encoder for the fixed registration fixture; no general decoder."""
    def head(major, n):
        if n < 24: return bytes([(major << 5) | n])
        for tag, size in ((24,1),(25,2),(26,4)):
            if n < 1 << (8*size): return bytes([(major << 5) | tag])+n.to_bytes(size,'big')
        raise ValueError('fixture_size')
    if type(value) is int: return head(0,value) if value >= 0 else head(1,-1-value)
    if type(value) is bytes: return head(2,len(value))+value
    if type(value) is str:
        raw=value.encode(); return head(3,len(raw))+raw
    if type(value) is dict:
        return head(5,len(value))+b''.join(cbor(k)+cbor(v) for k,v in value.items())
    raise TypeError('unsupported_fixture_type')


class SoftwareIdentity:
    def __init__(self, directory):
        self.directory=Path(directory)
        self.key=serialization.load_pem_private_key(private_read(self.directory/'key.pem',4096),None)
        if not isinstance(self.key,ec.EllipticCurvePrivateKey) or self.key.curve.name!='secp256r1':
            raise ValueError('test_key_profile')
        self.credential=private_read(self.directory/'credential.bin',32)
        if len(self.credential)!=32: raise ValueError('test_credential_size')
        self.used=set()

    @classmethod
    def create(cls, directory):
        path=Path(directory)
        path.mkdir(mode=0o700,exist_ok=False)
        key=ec.generate_private_key(ec.SECP256R1())
        retain(path/'key.pem',key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        retain(path/'credential.bin',os.urandom(32))
        return cls(path)

    def _options(self, raw, create=False):
        if type(raw) is not bytes or not 0<len(raw)<=16384: raise ValueError('test_options_bound')
        o=strict_json(raw)
        if type(o) is not dict or len(unb64(o.get('challenge')))!=32:
            raise ValueError('test_challenge')
        if (o.get('rp',{}).get('id') if create else o.get('rpId'))!='localhost':
            raise ValueError('test_rp_only')
        if o.get('extensions'): raise ValueError('test_extensions_not_allowed')
        if type(o.get('timeout')) not in (int,float) or not 0<o['timeout']<=300000:
            raise ValueError('test_deadline')
        challenge=o['challenge']
        if challenge in self.used or len(self.used)>=256: raise ValueError('test_challenge_replay_or_limit')
        self.used.add(challenge)
        return o

    def create_credential(self, raw):
        o=self._options(raw,True)
        if (o.get('attestation')!='none' or o.get('pubKeyCredParams')!=[{'type':'public-key','alg':-7}]
            or o.get('authenticatorSelection',{}).get('userVerification')!='required'
            or o.get('excludeCredentials')!=[]): raise ValueError('test_registration_profile')
        principal=unb64(o['user']['id'])
        if len(principal)!=32 or (self.directory/'principal.bin').exists():
            raise ValueError('one_test_enrollment_only')
        retain(self.directory/'principal.bin',principal)
        public=self.key.public_key().public_numbers()
        cose=cbor({1:2,3:-7,-1:1,-2:public.x.to_bytes(32,'big'),-3:public.y.to_bytes(32,'big')})
        # UP/UV are simulated only. They do not demonstrate user presence.
        auth=hashlib.sha256(b'localhost').digest()+b'\x45'+bytes(4)+bytes(16)+b'\x00\x20'+self.credential+cose
        client=canonical(dict(type='webauthn.create',challenge=o['challenge'],origin=ORIGIN,crossOrigin=False))
        return dict(credential_id=self.credential,client_data_json=client,
            attestation_object=cbor({'fmt':'none','authData':auth,'attStmt':{}}))

    def assert_credential(self, raw):
        o=self._options(raw)
        if o.get('userVerification')!='required': raise ValueError('test_uv_profile')
        allowed=o.get('allowCredentials',[])
        if allowed and not any(x.get('type')=='public-key' and unb64(x.get('id'))==self.credential for x in allowed):
            raise ValueError('different_credential_requested')
        principal=private_read(self.directory/'principal.bin',32)
        if len(principal)!=32: raise ValueError('test_principal')
        client=canonical(dict(type='webauthn.get',challenge=o['challenge'],origin=ORIGIN,crossOrigin=False))
        auth=hashlib.sha256(b'localhost').digest()+b'\x05'+bytes(4)
        signature=self.key.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
        return dict(credential_id=self.credential,authenticator_data=auth,client_data_json=client,
            signature=signature,user_handle=principal)


def enroll_software_identity():
    """Explicit root CLI step. Never called by a failed interactive login."""
    import asyncio
    import subprocess
    from savana import Client
    require_disposable_host()
    settings=strict_json(Path('/etc/savana/approvald-bootstrap-v2.json').read_bytes())
    if not any(p.get('profile')==1 and p.get('assurance')=='user_verified_passkey'
               for p in settings.get('enrollment_profiles',[])):
        raise ValueError('passkey_integration_deployment_required')
    identity=SoftwareIdentity.create(DIRECTORY)
    result=subprocess.run(['/usr/libexec/savana/savana-integration-admin','enroll'],
        capture_output=True,check=True,timeout=45)
    fields=dict(line.split('=',1) for line in result.stdout.decode().strip().splitlines())
    if set(fields)!={'enrollment','code','expires_at_unix_ms','browser'}:
        raise ValueError('closed_enrollment_output')
    # Real enrollment through the public Python SDK; no state-file edits.
    asyncio.run(Client().enroll(fields['enrollment'],fields['code'],identity,DIRECTORY/'identity.json'))
    principal=private_read(DIRECTORY/'principal.bin',32)
    value=dict(schema=1,mode=MODE,principal=principal.hex(),human_verification=False,
        hardware_attestation=False,production_acceptance=False)
    retain(PROFILE,canonical(value))
    return value


def arm_software_batch():
    require_disposable_host()
    registered=strict_json(private_read(PROFILE,4096))
    config=strict_json(Path('/var/lib/savana-benchmark/operator-bindings.json').read_bytes())
    if config.get('schema')!=3 or registered['mode']!=MODE: raise ValueError('finite_deployment_required')
    # Exclusive public metadata creation: no automatic rearming or expiry extension.
    value={**registered,'installation':config['provisioning']['installation'],
        'catalog_digest':catalog_digest(),'batch_id':os.urandom(32).hex(),
        'expires_at_unix_ms':time.time_ns()//1000000+900000}
    fd=os.open(PUBLIC_PROFILE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    try:
        data=canonical(value)
        if os.write(fd,data)!=len(data): raise OSError('profile_short_write')
        os.fchmod(fd,0o644);os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(PUBLIC_PROFILE.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return load_profile()


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['enroll','arm'])
    args=parser.parse_args()
    try: print(json.dumps(enroll_software_identity() if args.action=='enroll' else arm_software_batch()))
    except Exception as error:
        # No registration code, private key, assertion or exception repr.
        print(json.dumps(dict(status='not_confirmed',error_type=type(error).__name__)))
        raise SystemExit(2)
