
# ROBOT Recover

Detection and recovery for ROBOT (Return Of
Bleichenbacher's Oracle Threat).

Use threads to perform queries in parallel during the first phase of the recovery.

More Info at https://robotattack.org/

Usage
=====

```
$ python3 robot_recover.py

usage: robot_recover.py [-h] [-r RAW | -m MESSAGE | -f FILE] [-s] [-p int]
                        [-t] [-q] [--gcm | --cbc] [--csv]
                        host [s0] [limit]
```

host  : Target host domain  
-r, --raw  : Message to sign or decrypt (raw hex bytes)  
-m, --message  : Message to sign (text)  
-f, --file  : File with message to sign  
s0  : Start for s0 value (default 1)  
limit  : default="-1", s0 limit value (default -1 = no limit)  
-s, --recovery  : Try to recover if vulnerable  
-t, --nothread  : Disable parallel thread  
-p, --port  : TCP port (default=443)  
-q, --quiet  : Quiet (activated by default)  
--gcm  : Use only GCM/AES256  
--cbc  : Use only CBC/AES128  
--csv  : Output with CSV format  

There is also a scanner for domains. It takes as input a *domains.txt* file 
(one domain per line, or CSV with the domain in the first column), and it outputs 
in *results.csv* file.  
Build a *domains.txt* file list with domains, and then run :
```
$ python3 scan.py
```

Dependencies
============

This script needs only Python 3 (at least 3.6), there is no external dependency needed.

License
=======

This work is licensed as GPLv3, from the previous CC0 work.

Authors
=======

The attack proof of concept code was provided by Tibor Jager.

The detection was written by the ROBOT team :

Hanno Böck, Juraj Somorovsky, Craig Young

Then improved and updated by Antoine Ferron
