#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from pyroute2 import IPRoute
import ctypes
import socket
import ipaddress
import time

ipr = IPRoute()

text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

BPF_HASH(flowlabel_table, u64, u64, 256);
BPF_HISTOGRAM(flowlabels_set, u64, 256);
BPF_HISTOGRAM(flowlabels_received, u64, 256);
BPF_ARRAY(counts, u64, 1);

int get_flow_label(struct __sk_buff *skb)
{
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    // IPv6
    if (ethernet->type == 0x86DD)
    {
        struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));
        flowlabels_received.increment(ip6->flow_label);
        counts.increment(0);
        return -1;
    }
    else
    {
        return -1;
    }
}

int set_flow_label(struct __sk_buff *skb)
{
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    // IPv6
    if (ethernet->type == 0x86DD)
    {
        struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));

        u64 ip6_hi = ip6->dst_hi;
        u64 ip6_lo = ip6->dst_lo;

        u64 *flowlabel = flowlabel_table.lookup(&ip6_hi);
        u64 *flowlabel2 = flowlabel_table.lookup(&ip6_lo);

        if (flowlabel && flowlabel2 && *flowlabel == *flowlabel2) 
        {
            ip6->flow_label = *flowlabel;
            flowlabels_set.increment(*flowlabel);
        }

        return -1;
    }
    else
    {
        return -1;
    }
}

"""

try:
    b = BPF(text=text, debug=0)
    flowlabel_table = b.get_table('flowlabel_table')
    flowlabels_set = b.get_table('flowlabels_set')
    flowlabels_received = b.get_table('flowlabels_received')
    counts = b.get_table('counts')

    ip6_address_from_plugin = "abcd::1"
    bitpattern_from_plugin = 6
    ip6 = ipaddress.IPv6Address(ip6_address_from_plugin).exploded

    ip6_hi = int(ip6[0:4] + ip6[5:9] + ip6[10:14] + ip6[15:19], 16)
    ip6_lo = int(ip6[20:24] + ip6[25:29] + ip6[30:34] + ip6[35:39], 16)
    
    flowlabel_table[ctypes.c_ulong(ip6_hi)] = ctypes.c_ulong(bitpattern_from_plugin)
    flowlabel_table[ctypes.c_ulong(ip6_lo)] = ctypes.c_ulong(bitpattern_from_plugin)

    fn = b.load_func("get_flow_label", BPF.SCHED_CLS)
    fn2 = b.load_func("set_flow_label", BPF.SCHED_CLS)
    idx = ipr.link_lookup(ifname="lo")[0]
    #idx = ipr.link_lookup(ifname="eth0")[0]

    ipr.tc("add", "ingress", idx, "ffff:")
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)
    ipr.tc("add", "sfq", idx, "1:")
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn2.fd,
           name=fn.name, parent="1:", action="ok", classid=1)
finally:
    print("Hi")

    time.sleep(10)
    ipr.tc("del", "ingress", idx, "ffff:")
    ipr.tc("del", "sfq", idx, "1:")

    print("IPv6 packets received: ", counts[0].value)
    for item in flowlabels_set.items():
        print("Flow label set: ", item[0].value)
        print("Counts: ", item[1].value)

    for item in flowlabels_received.items():
        print("Flow label received: ", item[0].value)
        print("Counts: ", item[1].value)

print("BPF tc functionality - SCHED_CLS: OK")
