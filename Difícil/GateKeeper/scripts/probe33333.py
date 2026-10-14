import socket, time
ip='172.17.0.2'; port=33333
# Intento 1: conexión y espera larga
for attempt,payload in enumerate([b"", b"\n", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"SSH-2.0-OpenSSH_8.9\r\n"]):
    try:
        s=socket.socket(); s.settimeout(10)
        t0=time.time()
        s.connect((ip,port))
        print(f"[{attempt}] conectado en {time.time()-t0:.3f}s")
        if payload: s.sendall(payload)
        s.settimeout(8)
        try:
            d=s.recv(500)
            print(f"[{attempt}] recv {len(d)}: {d[:200]!r}")
        except socket.timeout:
            print(f"[{attempt}] timeout (sin datos)")
    except Exception as e:
        print(f"[{attempt}] error: {type(e).__name__}: {e}")
    finally:
        try: s.close()
        except: pass
    time.sleep(1)
