import socket

def banner_grab(host: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
                return data.decode(errors="ignore").strip()
            except Exception:
                try:
                    s.sendall(b"\r\n")
                    data = s.recv(1024)
                    return data.decode(errors="ignore").strip()
                except Exception:
                    return ""
    except Exception:
        return ""
