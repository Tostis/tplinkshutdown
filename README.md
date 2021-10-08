## tplinkshutdown

Simple python script to **reboot** a **TP-Link Powerline Adapter**.

Restarts TL-WPA8630 with <ip> using <password>. It can optionally restart the powerline adapter only if fails 5 ping attempts to <healthip>.

Does three http calls as result from reverse engineering of javascript GUI.
1) Call to /login?form=auth to obtain RSA modulus and exponent
2) Call to /login?form=login to send client side generated AES keypair
3) Call to /admin/reboot.json to invoke reboot

First two steps emulate an https handshake (over http) using an insecure RSA Textbook encryption.

### Install
```
pip install -r requirements.txt
pip3 install tplinkshutdown_tostis-x.x.x-py3-none-any.whl
```

### Usage
launch as script from *tplinkshutdown* folder
```
tplinkshutdown.py -p \<password> -i <ip> [-r <ip>]
tplinkshutdown.py --password=\<password> --ip=\<ip> [healthip=<ip>]

tplinkshutdown.py -p \<password> -o <hostname> [-r <ip>]
tplinkshutdown.py --password=\<password> --hostname=<hostname> [healthip=<ip>]

tplinkshutdown.py -p \<password> -m <macaddress> [-r <ip>]
tplinkshutdown.py --password=\<password> --mac=<macaddress> [healthip=<ip>]
```
the mac address option needs root access and is useful as workaround for [Powerline Extender Acting as the DHCP server](https://community.tp-link.com/en/home/forum/topic/265692)


or launch as module from everywhere
```
python3.8 -m tplinkshutdown.main
```

or launch the shell script
```
/home/<user>/.local/bin/tplinkshutdown 
```

### Exit values
The program terminates with the error numbers

| Return value | Error                |
|---|------------------------------|
| 0 | Everything ok                |
| 2 | Wrong command line arguments |
| 3 | Error during login           |
| 4 | Error during reboot          |
| 5 | Network error during phase 1: obtain cerificate          |
| 6 | Network error during phase 2: login          |
| 6 | Network error during phase 3: reboot          |

### Requirements

- Python 3.x 

### Dependencies

See requirements.txt

### Create wheel package
```
.\venv\Scripts\python.exe .\setup.py sdist bdist_wheel
```

### Crypto problem

https://github.com/openthread/openthread/issues/1137

```
pip install crypto
pip install pycryptodome
Change crypto to Crypto in the Library->site-packages folder of my virtual environment
```

### FreeBSD problem
To solve this error
```
Traceback (most recent call last):
  File "/usr/local/lib/python3.8/runpy.py", line 194, in _run_module_as_main
    return _run_code(code, main_globals, None,
  File "/usr/local/lib/python3.8/runpy.py", line 87, in _run_code
    exec(code, run_globals)
  File "/usr/local/lib/python3.8/site-packages/tplinkshutdown/main.py", line 7,in <module>
    from scapy.layers.l2 import Ether, ARP
  File "/usr/local/lib/python3.8/site-packages/scapy/layers/l2.py", line 17, in<module>
    from scapy.ansmachine import AnsweringMachine
  File "/usr/local/lib/python3.8/site-packages/scapy/ansmachine.py", line 20, in <module>
    from scapy.sendrecv import send, sniff
  File "/usr/local/lib/python3.8/site-packages/scapy/sendrecv.py", line 61, in <module>
    import scapy.route  # noqa: F401
  File "/usr/local/lib/python3.8/site-packages/scapy/route.py", line 218, in <module>
    conf.route = Route()
  File "/usr/local/lib/python3.8/site-packages/scapy/route.py", line 37, in __init__
    self.resync()
  File "/usr/local/lib/python3.8/site-packages/scapy/route.py", line 45, in resync
    from scapy.arch import read_routes
  File "/usr/local/lib/python3.8/site-packages/scapy/arch/__init__.py", line 124, in <module>
    from scapy.arch.bpf.supersocket import *  # noqa F403
  File "/usr/local/lib/python3.8/site-packages/scapy/arch/bpf/supersocket.py", line 27, in <module>
    from scapy.layers.l2 import Loopback
ImportError: cannot import name 'Loopback' from partially initialized module 'scapy.layers.l2' (most likely due to a circular import) (/usr/local/lib/python3.8/site-packages/scapy/layers/l2.py)
```
see https://github.com/secdev/scapy/pull/3247/files

You should apply this patch

scapy/arch/bpf/supersocket.py
```
@@ -24,7 +24,6 @@
from scapy.interfaces import network_name
from scapy.supersocket import SuperSocket
from scapy.compat import raw
-from scapy.layers.l2 import Loopback


if FREEBSD:
@@ -375,6 +374,7 @@ def recv(self, x=BPF_BUFFER_LENGTH):

    def send(self, pkt):
        """Send a packet"""
+        from scapy.layers.l2 import Loopback

        # Use the routing table to find the output interface
        iff = pkt.route()[0]
```



### Notes

Tested with
- TL-WPA8630 Hardware Revision v2.0 Firmware Version v2.0.3 Build 20190910 Rel. 49754

#### TrueNAS Core (FreeBSD)
Jail must be in the same network as TP-Link. Make sure you uncheck "NAT" into jail settings.

### License
Distributed under GNU GPLv3.

### Contributing
Pull request are wellcome.

### Donate
If you like this project you can donate.

[![bitcoin-qrcode](https://github.com/Tostis/tplinkshutdown/donate-bitcoin.png)](https://github.com/Tostis/tplinkshutdown/bitcoin-address.txt)
