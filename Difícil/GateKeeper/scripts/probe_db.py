import socket, time, struct

def handshake(ip, port, label):
    print(f"\n===== {label} ({port}) =====")
    s = socket.socket(); s.settimeout(5)
    t0=time.time()
    try:
        s.connect((ip, port))
        # MySQL: server sends handshake first
        try:
            data = s.recv(300)
            print(f"[+{time.time()-t0:.3f}s] recv {len(data)} bytes (handshake esperado): {data[:120]!r}")
        except socket.timeout:
            print("[!] timeout esperando handshake de MySQL (raro para MySQL real)")
        # Now send a malformed packet to elicit error
        s.send(b'\x00'*32)
        time.sleep(0.3)
        try:
            data = s.recv(300)
            print(f"[respuesta] {data[:160]!r}")
        except socket.timeout:
            print("[!] sin respuesta")
    except Exception as e:
        print("ERROR", e)
    finally:
        s.close()

ip='172.17.0.2'
handshake(ip,3306,'MySQL')
handshake(ip,5432,'PostgreSQL')
