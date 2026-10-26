"""Container setup and supervision; reuse the normal application and installer."""
from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

from ft_package import APPS, SOURCE, INSTALLED, atomic, copy_code, product, sha

APP = Path('/app')
RUN = Path('/run/filetrust')
ENVIRONMENT = Path('/opt/filetrust-env')
STOP = False


def private_bytes(path, raw):
    if path.is_symlink(): raise ValueError('Private runtime paths must not be symbolic links')
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o600); output.write(raw)


def initialize(uid, gid):
    if os.geteuid() != 0: raise ValueError('Only volume initialization uses container root')
    if not 0 < uid < 2**31 or not 0 < gid < 2**31: raise ValueError('Use a non-root container uid and gid')
    if APP.is_symlink(): raise ValueError('Application volume must not be a symlink')
    owner = APP / '.container-owner.json'
    if owner.exists():
        if json.loads(owner.read_text()) != {'uid': uid, 'gid': gid}:
            raise ValueError('This node belongs to another uid/gid. Restore its original container identity; no permissions changed.')
    elif any(APP.iterdir()): raise ValueError('Unrecognized existing volume; refusing to adopt or overwrite its data')
    os.chown(APP, uid, gid); APP.chmod(0o700)
    atomic(owner, {'uid': uid, 'gid': gid}); os.chown(owner, uid, gid)


def stage(name):
    if name not in ('github-token', 'browser-input', 'xauth-input'): raise ValueError('Unsupported temporary credential')
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536: raise ValueError('Temporary credential exceeds size limit')
    if name == 'github-token':
        from github_auth import validate_token
        raw = validate_token(raw.decode()).encode()
    private_bytes(RUN / name, raw)


def login():
    path = RUN / 'github-token'
    if path.exists():
        if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid():
            raise ValueError('Private download access is not owner-only')
        from github_auth import validate_token
        os.environ['GH_TOKEN'] = validate_token(path.read_text()); path.unlink()


def verify_code():
    manifest = json.loads((APP / INSTALLED).read_text())
    if manifest.get('product') != product(): raise ValueError('Application volume belongs to a different product')
    if (APP / 'VERSION').read_bytes() != (SOURCE / 'VERSION').read_bytes():
        raise ValueError('Image and installed code versions differ; run Docker update while stopped')
    for name, row in manifest['files'].items():
        if 'contracts' in Path(name).parts: continue
        if not (APP / name).is_file() or sha(APP / name) != row['sha256']:
            raise ValueError('Installed code changed: ' + name + '; use install/update while stopped to recover')


def settings():
    data = json.loads((APP / '.container-settings.json').read_text())
    kind = product() in ('do', 'req')
    if data['mode'] not in (('desktop', 'browser') if kind else ('headless',)):
        raise ValueError('Invalid display mode')
    if kind:
        for key in ('web_port', 'vnc_port'):
            if type(data[key]) is not int or not 1024 <= data[key] <= 65535: raise ValueError('Choose ports between 1024 and 65535')
        if data['web_port'] == data['vnc_port']: raise ValueError('Browser and VNC ports must differ')
    return data


def configure(arguments, allow_extra=True):
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['desktop', 'browser'])
    parser.add_argument('--web-port', type=int)
    parser.add_argument('--vnc-port', type=int)
    args, rest = parser.parse_known_args(arguments)
    if rest and not allow_extra: raise ValueError('Unknown display option; use install to change native application settings')
    app = product(); gui = app in ('do', 'req')
    old = json.loads((APP / '.container-settings.json').read_text()) if (APP / '.container-settings.json').exists() else {}
    mode = args.mode or old.get('mode')
    if gui and mode is None:
        mode = input('Interface: desktop or browser [browser]: ').strip().lower() or 'browser'
    if not gui: mode = 'headless'
    data = {'mode': mode, 'web_port': args.web_port or old.get('web_port', 6080 if app == 'do' else 6081),
            'vnc_port': args.vnc_port or old.get('vnc_port', 15900 if app == 'do' else 15901)}
    if mode not in (('desktop','browser') if gui else ('headless',)): raise ValueError('Choose desktop or browser')
    if gui and (any(not 1024 <= data[key] <= 65535 for key in ('web_port','vnc_port')) or data['web_port'] == data['vnc_port']):
        raise ValueError('Choose two different ports between 1024 and 65535')
    if mode == 'browser' and not (APP / '.browser-auth').exists():
        temporary = RUN / 'browser-input'
        if temporary.exists():
            password = temporary.read_text().rstrip('\r\n'); temporary.unlink()
        else:
            if not sys.stdin.isatty(): raise ValueError('Browser setup needs a terminal password prompt or FILETRUST_BROWSER_PASSWORD_FILE')
            password = getpass.getpass('Browser access password (8 printable characters; separate from wallet password): ')
            if password != getpass.getpass('Repeat browser access password: '): raise ValueError('Passwords differ')
        if len(password) != 8 or any(not 33 <= ord(c) <= 126 for c in password): raise ValueError('VNC access requires exactly 8 printable ASCII characters')
        from Crypto.Cipher import DES
        # Standard VNC password-file encoding. This access password is separate
        # from the application's encrypted wallet and never travels in argv.
        # LibVNC's DES key uses the RFB bit order, including this public
        # password-file format constant (not a wallet or authentication secret).
        key = bytes(int(f'{b:08b}'[::-1], 2) for b in [23,82,107,6,35,78,88,7])
        encoded = DES.new(key, DES.MODE_ECB).encrypt(password.encode())
        private_bytes(APP / '.browser-auth', encoded)
    atomic(APP / '.container-settings.json', data)
    return rest


def install(arguments):
    login(); copy_code(SOURCE, APP)
    link = APP / '.venv'
    if link.exists() and not link.is_symlink(): raise ValueError('An existing native Python environment cannot be adopted silently')
    if link.is_symlink() and link.resolve() != ENVIRONMENT: raise ValueError('Container Python environment link was changed')
    if not link.is_symlink(): link.symlink_to(ENVIRONMENT, target_is_directory=True)
    native = configure(arguments)
    if product() in ('reporter', 'discovery'): native += ['--no-service']
    if '--menu' in native: raise ValueError('Desktop menu integration belongs to the native installer')
    subprocess.run(['bash', str(APP / 'install.sh'), *native], cwd=APP, check=True)
    print('Docker setup complete. Use ./docker.sh start when ready.', flush=True)


def health():
    try:
        start = json.loads((RUN / 'start.json').read_text())
        os.kill(start['pid'], 0)
        if start['gui']:
            os.kill(start['app_pid'], 0)
            data = settings()
            if data['mode'] == 'browser':
                from urllib.request import urlopen
                with urlopen(f'http://127.0.0.1:{data["web_port"]}/vnc.html', timeout=2) as response:
                    return response.status == 200
            return True  # Includes the normal wallet-unlock dialog.
        ready = json.loads((APP / '.filetrust-node-health.json').read_text())
        return ready['pid'] == start['pid'] and ready['ready_at'] >= start['started_at'] and ready['version'] == (SOURCE / 'VERSION').read_text().strip()
    except (OSError,ValueError,KeyError,TypeError): return False


def xauthority(path, display, cookie):
    fields = (b'', str(display).encode(), b'MIT-MAGIC-COOKIE-1', cookie)
    private_bytes(path, struct.pack('>H', 65535) + b''.join(struct.pack('>H',len(part))+part for part in fields))


def wait_lock():
    path = APP / '.filetrust-updates/run.lock'
    if path.exists():
        with path.open('rb') as lock: fcntl.flock(lock, fcntl.LOCK_EX)


def display_number(reader, timeout=20):
    """Keep the pipe open until Xvfb finishes its newline-terminated reply."""
    deadline = time.monotonic() + timeout
    raw = b''
    try:
        while b'\n' not in raw:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([reader], [], [], remaining)[0]:
                raise ValueError('Virtual display did not become ready')
            part = os.read(reader, 32)
            if not part or len(raw) + len(part) > 32:
                raise ValueError('Invalid virtual display response')
            raw += part
        if not raw.endswith(b'\n') or not raw[:-1].isdigit():
            raise ValueError('Invalid virtual display response')
        return raw[:-1].decode('ascii')
    finally:
        os.close(reader)


def run_gui(data):
    global STOP
    STOP = False
    signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__('STOP', True))
    env = {**os.environ, 'XAUTHORITY': str(RUN / 'Xauthority')}
    children = []; application = None
    def spawn(args, **kwargs):
        process = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, **kwargs)
        children.append(process); return process
    try:
        if data['mode'] == 'browser':
            # Xvfb must reserve its abstract socket too: host networking
            # otherwise lets an existing desktop answer the same display.
            # -displayfd chooses an available number for both transports.
            display_dir = Path('/tmp/.X11-unix')
            display_dir.mkdir(mode=0o1777, exist_ok=True)
            cookie = os.urandom(16); xauthority(RUN / 'Xauthority', '', cookie)
            reader, writer = os.pipe()
            spawn(['Xvfb','-displayfd',str(writer),'-screen','0','1280x900x24','-nolisten','tcp','-auth',str(RUN / 'Xauthority')], pass_fds=(writer,))
            os.close(writer)
            display = display_number(reader)
            env['DISPLAY'] = ':' + display; xauthority(RUN / 'Xauthority', display, cookie)
            spawn(['openbox','--sm-disable'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            spawn(['x11vnc','-display',env['DISPLAY'],'-auth',str(RUN / 'Xauthority'),'-rfbauth',str(APP / '.browser-auth'),
                   '-rfbport',str(data['vnc_port']),'-localhost','-forever','-shared','-noxdamage','-noshm','-quiet'])
            spawn(['/usr/bin/websockify','--web=/usr/share/novnc/','127.0.0.1:'+str(data['web_port']),'127.0.0.1:'+str(data['vnc_port'])])
            print(f'Browser interface: http://127.0.0.1:{data["web_port"]}/vnc.html (browser access password required)',flush=True)
        else:
            deadline = time.monotonic()+30
            while not (RUN/'xauth-input').exists():
                if STOP: return 0
                if time.monotonic()>deadline: raise ValueError('Desktop authorization was not provided; use a local X11/XWayland session')
                time.sleep(.1)
            text=(RUN/'xauth-input').read_text(); (RUN/'xauth-input').unlink()
            result=subprocess.run(['xauth','-f',str(RUN/'Xauthority'),'nmerge','-'],input=text,text=True,capture_output=True)
            if result.returncode: raise ValueError('Desktop authorization could not be loaded')
        application = subprocess.Popen([str(ENVIRONMENT/'bin/python'),'-u',str(APP/APPS[product()][0])],cwd=APP,env=env,stdin=subprocess.DEVNULL)
        atomic(RUN/'start.json',{'pid':os.getpid(),'app_pid':application.pid,'started_at':time.time(),'gui':True})
        while application.poll() is None:
            if STOP:
                print('Waiting for the application and active transfers to finish...',flush=True)
                application.terminate(); application.wait(); break
            if any(child.poll() is not None for child in children): raise ValueError('A display service stopped; inspect container logs')
            time.sleep(.2)
        wait_lock()
        return application.returncode or 0
    finally:
        if application is not None and application.poll() is None:
            application.terminate(); application.wait(); wait_lock()
        for child in reversed(children):
            if child.poll() is None: child.terminate()
        for child in children:
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: child.kill(); child.wait()


def run():
    verify_code(); os.environ.pop('GH_TOKEN',None);os.environ.pop('GITHUB_TOKEN',None)
    data=settings()
    if product() in ('do','req'):
        sys.path.insert(0,str(APP))
        import ft_transfer
        descriptor=json.loads((APP/'vaultmesh-release.json').read_text())['assets']['linux-amd64']
        binary=APP/'core/vaultmesh'
        if not binary.is_file() or ft_transfer.digest(binary)!=descriptor['sha256']: raise ValueError('Transfer program is missing or changed; rerun Docker install')
        return run_gui(data)
    atomic(RUN/'start.json',{'pid':os.getpid(),'started_at':time.time(),'gui':False})
    os.chdir(APP)
    os.execv(str(ENVIRONMENT/'bin/python'),[str(ENVIRONMENT/'bin/python'),'-u',str(APP/APPS[product()][0])])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['init','idle','stage-token','stage-browser','stage-xauth','install','configure','sync','run','health','settings','check','doctor','network-config'])
    parser.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    if args.command=='init': initialize(*map(int,args.arguments));return 0
    if os.geteuid()==0: raise ValueError('Application operations must use the non-root node uid')
    if args.command=='idle':
        signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
        while True: signal.pause()
    if args.command.startswith('stage-'):
        stage({'stage-token':'github-token','stage-browser':'browser-input','stage-xauth':'xauth-input'}[args.command]);return 0
    if args.command=='health':return 0 if health() else 1
    if args.command=='settings':
        data=settings();print(data['mode'],data['web_port'],data['vnc_port']);return 0
    if args.command=='run':return run()
    login()
    if product() in ('do','req'): sys.path.insert(0,str(APP/'core'))
    if args.command=='install':install(args.arguments);return 0
    if args.command=='configure':
        from ft_package import stopped
        with stopped(APP):configure(args.arguments, allow_extra=False)
        return 0
    if args.command=='sync':
        copy_code(SOURCE,APP)
        if product() in ('do','req'):
            sys.path.insert(0,str(APP));from ft_transfer import install as transfer;transfer(APP)
        return 0
    if args.command=='check':
        sys.path.insert(0,str(APP))
        module = 'core.ft_updates' if product() in ('do','req') else 'ft_updates'
        import importlib
        cli = importlib.import_module(module).cli
        sys.argv=[str(APP/'update.py'),*args.arguments];return cli(APP)
    if args.command=='doctor':
        sys.path.insert(0,str(APP))
        verify_code()
        if not (APP/'config.json').is_file() or (APP/'config.json').stat().st_mode & 0o077:
            raise ValueError('Installed configuration must be owner-only')
        if product() in ('do','req'):
            import ft_transfer
            row=json.loads((APP/'vaultmesh-release.json').read_text())['assets']['linux-amd64']
            if ft_transfer.digest(APP/'core/vaultmesh')!=row['sha256']:raise ValueError('Transfer executable differs from its release pin')
        from ft_network_config import cli
        return cli(APP,['check'])
    sys.path.insert(0,str(APP))
    from ft_network_config import cli
    return cli(APP,args.arguments)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as exc:
        print('Container operation stopped: '+(str(exc) if isinstance(exc,(ValueError,PermissionError)) else type(exc).__name__),file=sys.stderr)
        raise SystemExit(1)
