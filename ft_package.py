"""Package lifecycle boundaries shared by the four independent applications.

Application algorithms stay in their original programs. A source manifest
limits installation/image updates to shipped code; identities and user data
are never inferred from a developer working tree or overwritten by code copy.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
APPS = {'do': ('DO.py', 'Data Owner'), 'req': ('REQ.py', 'Requester'),
        'reporter': ('reporter.py', 'Reporter'), 'discovery': ('discovery_nodes.py', 'Discovery')}
MANIFEST = 'package-files.json'
INSTALLED = '.container-code.json'
PRIVATE = {'config.json', 'keyvault.json', 'requester_keys.json', 'wallet.json', 'unlock.key',
           'policies.json', 'directory_cache.json', 'recovery_pending.json', 'network_config_state.json',
           'trusted_owners.json', 'sync_state.json', 'network-config-active.json', '.filetrust-node-health.json'}
DATA = {'.git', '.venv', '.filetrust-updates', '.network-updates', '.filetrust-docker',
        'logs', 'log', 'runtime', 'pieces', 'data', 'data_unzipped', 'keys', 'pid_records',
        'upload_zips', 'dkg_public_keys', 'transfer_jobs', 'storage_verification_queue', 'drop',
        'networks', 'dkg-recovery-v1', 'files', 'tests', '__pycache__'}


def product(source=None):
    source = SOURCE if source is None else source
    value = json.loads((Path(source) / 'update-source.json').read_text())['product']
    if value not in APPS:
        raise ValueError('Unsupported application package')
    return value


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def public_path(name):
    if not isinstance(name, str): return False
    part = PurePosixPath(name)
    return (isinstance(name, str) and part.as_posix() == name and not part.is_absolute()
            and not any(p.startswith('.') and p not in {'.gitignore', '.dockerignore'} for p in part.parts)
            and '\\' not in name and not any(p in {'.', '..'} or p in DATA for p in part.parts)
            and part.name not in PRIVATE and name not in {MANIFEST, INSTALLED}
            and not part.name.endswith(('.pyc', '.log', '.jsonl', '.key', '.db')))


def safe_target(root, name):
    if not public_path(name):
        raise ValueError('Package contains an unsafe code path')
    target = root.joinpath(*PurePosixPath(name).parts)
    if any(p.is_symlink() for p in (target, *target.parents)):
        raise ValueError('Package paths must not follow symbolic links')
    return target


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError('Managed files must not be symbolic links')
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.package-')
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, indent=2)
            output.write('\n')
            output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def source_manifest(source=None):
    source = Path(SOURCE if source is None else source)
    data = json.loads((source / MANIFEST).read_text())
    if data.get('schema') != 1 or data.get('product') != product(source) or not isinstance(data.get('files'), dict):
        raise ValueError('Invalid package source manifest')
    for name, row in data['files'].items():
        path = safe_target(source, name)
        if not path.is_file() or sha(path) != row['sha256'] or path.stat().st_size != row['size']:
            raise ValueError('Package source changed: ' + name + '; use a complete reviewed checkout')
        if row['mode'] not in (0o644, 0o755):
            raise ValueError('Invalid package code mode')
    return data


@contextlib.contextmanager
def stopped(root):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    handles = []
    try:
        control = root / '.filetrust-updates'
        control.mkdir(exist_ok=True, mode=0o755)
        for path in (control / 'update.lock', control / 'run.lock', root / '.run.lock'):
            if path.is_symlink(): raise ValueError('Application locks must not be symbolic links')
            handle = path.open('a+')
            try: fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                handle.close()
                raise ValueError('Stop this application and its workers before changing its installation') from None
            handles.append(handle)
        journal = control / 'journal.json'
        if journal.exists() and json.loads(journal.read_text()).get('phase') in ('applying', 'recovering'):
            raise ValueError('Recover the interrupted signed update before replacing code')
        yield
    finally:
        for handle in reversed(handles): handle.close()


def copy_code(source, target):
    """No supplied config, wallet, share, downloaded ABI or user file is replaced."""
    source, target = Path(source), Path(target)
    data = source_manifest(source)
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink(): raise ValueError('Application directory cannot be a symbolic link')
    with stopped(target):
        previous_path = target / INSTALLED
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else {'files': {}}
        if previous.get('product', data['product']) != data['product']:
            raise ValueError('This volume belongs to a different application; use a separate Docker project')
        selected = []
        removed = []
        for name, row in data['files'].items():
            dst = safe_target(target, name)
            # ABIs installed from the network describe this identity's network.
            if (target / 'config.json').exists() and ('contracts' in PurePosixPath(name).parts): continue
            if dst.exists():
                expected = previous['files'].get(name)
                current = sha(dst)
                if current != row['sha256'] and (not expected or current != expected['sha256']):
                    raise ValueError('Locally modified code: ' + name + '; source and node data retained')
            selected.append((name, row, dst))
        for name, row in previous['files'].items():
            if name in data['files'] or 'contracts' in PurePosixPath(name).parts: continue
            path = safe_target(target, name)
            if path.exists():
                if sha(path) != row['sha256']: raise ValueError('Locally modified retired code: ' + name)
                removed.append(path)
        # Stage every verified file before replacing any current code.
        with tempfile.TemporaryDirectory(prefix='.code-stage-', dir=target) as temporary:
            staged = []
            for number, (name, row, dst) in enumerate(selected):
                ready = Path(temporary) / str(number)
                shutil.copyfile(source / name, ready); ready.chmod(row['mode'])
                staged.append((ready, dst))
            for ready, dst in staged:
                dst.parent.mkdir(parents=True, exist_ok=True)
                os.replace(ready, dst)
            for path in removed: path.unlink()
        atomic(previous_path, data)


def native_deploy(arguments):
    """Run a standard root service from /opt as its own unprivileged account."""
    if os.geteuid() != 0: raise ValueError('System installation requires sudo')
    app = product()
    if app not in ('reporter', 'discovery'): raise ValueError('GUI applications install as the desktop user')
    target = Path('/opt') / ('filetrust-' + app)
    if SOURCE != target and (SOURCE / 'config.json').exists():
        raise ValueError('This source folder already has node state. Use --no-service here, or migrate that state explicitly; no new wallet was created.')
    state = subprocess.run(['systemctl', 'is-active', '--quiet', 'filetrust-' + app])
    if state.returncode == 0: raise ValueError('Stop the existing service before reinstalling')
    if SOURCE != target: copy_code(SOURCE, target)
    import pwd
    account_name = 'ft' + app
    try: account = pwd.getpwnam(account_name)
    except KeyError:
        subprocess.run(['useradd', '--system', '--user-group', '--home-dir', str(target), '--no-create-home', '--shell', '/usr/sbin/nologin', account_name], check=True)
        account = pwd.getpwnam(account_name)
    os.chown(target, account.pw_uid, account.pw_gid)
    env = {**os.environ, 'FILETRUST_NATIVE_INSTALLED': '1', 'FILETRUST_INSTALL_BANNER_SHOWN': '1'}
    try:
        subprocess.run(['bash', str(target / 'install.sh'), *arguments], env=env, check=True)
    finally:
        for path in (target, *target.rglob('*')):
            os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)


def uninstall(purge=False, user_service=False):
    app = product()
    # The chosen command owns this installation only. A source/user install
    # must never redirect removal to another node under /opt.
    root = SOURCE
    if root.is_symlink(): raise ValueError('Refusing a symbolic-link application directory')
    if purge:
        print('This deletes this installation\'s wallet, settings and managed data. Retire duties and back up first.', flush=True)
        if not sys.stdin.isatty() or input('Type DELETE to purge this installation: ') != 'DELETE':
            raise ValueError('Cancelled; nothing changed')
    if app in ('reporter', 'discovery'):
        scope = ['--user'] if user_service else []
        unit = 'filetrust-' + app + '.service'
        info = subprocess.run(['systemctl', *scope, 'show', unit, '-p', 'WorkingDirectory', '--value'], capture_output=True, text=True)
        if info.returncode == 0 and info.stdout.strip() == str(root):
            subprocess.run(['systemctl', *scope, 'disable', '--now', unit], check=True)
            unit_path = ((Path.home() / '.config/systemd/user') if user_service else Path('/etc/systemd/system')) / unit
            if unit_path.is_symlink(): raise ValueError('Refusing a symbolic-link service unit')
            unit_path.unlink(missing_ok=True)
            subprocess.run(['systemctl', *scope, 'daemon-reload'], check=True)
    with stopped(root):
        if (root / '.venv').is_symlink(): raise ValueError('Native uninstaller cannot remove a container installation')
        if (root / '.venv').exists(): shutil.rmtree(root / '.venv')
        entry = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'applications' / ('filetrust-' + app + '.desktop')
        if entry.exists() and str(root) in entry.read_text(): entry.unlink()
        if purge:
            for name in sorted(PRIVATE | (DATA - {'.git', '.venv', 'tests', 'files', '__pycache__'})):
                path = root / name
                if path.is_symlink(): raise ValueError('Managed data cannot be symbolic links; external data retained')
            for name in sorted(PRIVATE | (DATA - {'.git', '.venv', 'tests', 'files', '__pycache__'})):
                path = root / name
                if path.is_dir(): shutil.rmtree(path)
                else: path.unlink(missing_ok=True)
    print('Runtime removed. ' + ('Managed account/state purged.' if purge else 'Wallet, settings and data retained.'))
    print('Source files, shared OS packages, external files and inactive service accounts are kept.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['native-deploy', 'uninstall'])
    parser.add_argument('--purge', action='store_true')
    parser.add_argument('--user', action='store_true')
    args, extra = parser.parse_known_args()
    if args.command == 'native-deploy': native_deploy(extra)
    else:
        if extra: raise ValueError('Unknown uninstall options')
        uninstall(args.purge, args.user)


if __name__ == '__main__':
    try: main()
    except (Exception, KeyboardInterrupt) as exc:
        print('Package operation stopped: ' + (str(exc) if isinstance(exc, (ValueError, PermissionError)) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
