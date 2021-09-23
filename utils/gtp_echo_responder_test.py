#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# Author: Pau Espin Pedrol <pespin@sysmocom.de>
#
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice (including the next
# paragraph) shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import socket
import argparse
import struct
from ipaddress import ip_address, IPv4Address

GTP1C_PORT = 2123
BUF_SIZE = 4096

GTP_HDRv1_FLAG_PN = (1<<0)
GTP_HDRv1_FLAG_S = (1<<1)
GTP_HDRv1_FLAG_E = (1<<2)
GTP_HDRv1_PT_GTP = (1<<4)
GTP_HDRv1_VER_GTP1 = (1<<5)

GTP_HDRv2_FLAG_T = (1<<3)
GTP_HDRv2_FLAG_P = (1<<4)
GTP_HDRv2_VER_GTP2 = (2<<5)

def gen_gtpc_v1_hdr(flags, type, length, tei, seq=0, npdu=0, next=0):
    spare = 0
    if (flags & (GTP_HDRv1_FLAG_PN|GTP_HDRv1_FLAG_S|GTP_HDRv1_FLAG_E)):
        #long format
        length += 4
        d = struct.pack('!BBHIHBB', flags, type, length, tei, seq, npdu, next)
    else:
        #short format
        d = struct.pack('!BBHI', flags, type, length, tei)
    return d

def gen_gtpc_v2_hdr(flags, type, length, tei=0, seq=0):
    spare = 0
    if (flags & (GTP_HDRv2_FLAG_T)):
        #long format, with TEI
        length += 4 + 4
        d = struct.pack('!BBHIHBB', flags, type, length, tei, seq >> 8, seq & 0xff, spare)
    else:
        #short format
        length += 4
        d = struct.pack('!BBHHBB', flags, type, length, seq >> 8, seq & 0xff, spare)
    return d

def gen_gtpc_v1_echo_req(tei=0, append_flags=0, seq=0, npdu=0, next=0):
    return gen_gtpc_v1_hdr(GTP_HDRv1_VER_GTP1 | GTP_HDRv1_PT_GTP | append_flags, 1, 0, tei, seq, npdu, next)

def gen_gtpc_v2_echo_req(append_flags=0, seq=0, recovery=0, node_features=-1):
    length = 0
    payload = b''
    if (recovery > 0):
        recovery_ie = struct.pack('!BHBB', 3, 1, 0, recovery)
        payload += recovery_ie
        length += len(recovery_ie)
    if (node_features > 0):
        node_features_ie = struct.pack('!BHBB', 152, 1, 0, node_features)
        payload += node_features_ie
        length += len(node_features_ie)
    return gen_gtpc_v2_hdr(GTP_HDRv2_VER_GTP2 | append_flags, 1, length, 0, seq) + payload

def tx_rx(sk, rem_addr, tx_buf, exp_rx = True):
    print('Tx ECHO_REQ to %r: %r' % (repr(rem_addr), repr(tx_buf)))
    sk.sendto(tx_buf, rem_addr)
    if exp_rx:
        rx_buf = sk.recvfrom(BUF_SIZE)
        msg = "Message from Server {}".format(rx_buf)
        print(msg)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Tester for gtp-echo-recorder.')
    p.add_argument('-l', '--local-address', default='127.0.0.2', help="Local GTP address")
    p.add_argument('-r', '--remote-address', default='127.0.0.1', help="Remote GTP address")
    args = p.parse_args()

    print('Binding socket on %r...' % repr((args.local_address, GTP1C_PORT)))
    family = socket.AF_INET if type(ip_address(args.local_address)) is IPv4Address else socket.AF_INET6
    sk = socket.socket(family=family, type=socket.SOCK_DGRAM)
    sk.bind((args.local_address, GTP1C_PORT));

    rem_addr = (args.remote_address, GTP1C_PORT)

    tx_rx(sk, rem_addr, gen_gtpc_v1_echo_req())
    tx_rx(sk, rem_addr, gen_gtpc_v1_echo_req(1, GTP_HDRv1_FLAG_S, seq=67))
    tx_rx(sk, rem_addr, gen_gtpc_v2_echo_req(0, seq=300, recovery=-1, node_features=-1))
    tx_rx(sk, rem_addr, gen_gtpc_v2_echo_req(0, seq=20, recovery=99, node_features=-1))
    tx_rx(sk, rem_addr, gen_gtpc_v2_echo_req(0, seq=20, recovery=100, node_features=0xbb))
