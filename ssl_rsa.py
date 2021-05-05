# -*- coding: utf-8 -*-
#
# TLS certificate reading for ROBOT-recover
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


import hashlib
import socket
import ssl
import asn1


def asn2object(asn_bytes):
    decoder = asn1.Decoder()
    decoder.start(asn_bytes)
    # Sequence or set are all output as a list
    output_obj = []
    while not decoder.eof():
        tag = decoder.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = decoder.read()
            output_obj.append(value)
        elif tag.typ == asn1.Types.Constructed:
            decoder.enter()
            output_obj.append(asn2object(decoder.m_stack[-1][1]))
            decoder.leave()
        else:
            raise Exception("Should be primitive or constructed")
    return output_obj


def get_rsakey(x509cert_object):
    # Extract subjectPublicKeyInfo - rsaEncryption
    #  modulus and exponent
    pubkey_info = x509cert_object[0][0][6]
    if pubkey_info[0][0] != "1.2.840.113549.1.1.1":
        raise Exception("Expect RSAES-PKCS1-v1_5 encryption scheme for the public key")
    key_asn = pubkey_info[1][1:]
    # Return [n, e]
    return asn2object(key_asn)[0]


def get_rsa_from_server(server, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("RSA")
    raw_socket = socket.socket()
    raw_socket.settimeout(timeout)
    with ctx.wrap_socket(raw_socket) as s:
        s.connect((server, port))
        cert_raw = s.getpeercert(binary_form=True)
        s.close()
        cert_obj = asn2object(cert_raw)
        pubkey = get_rsakey(cert_obj)
        cert_fp = hashlib.sha256(cert_raw).hexdigest().upper()
        return (*pubkey, cert_fp)
