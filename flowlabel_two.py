#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from pyroute2 import IPRoute
import ctypes
import socket
import ipaddress

ipr = IPRoute()

text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>
BPF_HASH(flowlabel_table, u64, u64, 256);

int get_flow_label(struct __sk_buff *skb)
{
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    // IPv6
    if (ethernet->type == 0x86DD)
    {
        //bpf_trace_printk("got an IPv6 packet\\n");
        //bpf_trace_printk("%d\\n", skb->len);
        struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));
        //bpf_trace_printk("%d\\n", ip6->flow_label);
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
        bpf_trace_printk("got an IPv6 packet\\n");
        //bpf_trace_printk("%d\\n", skb->len);
        struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));
        //long *foo = flowlabel_table.lookup(&zero);

        u64 ip6_hi = ip6->dst_hi;
        u64 ip6_lo = ip6->dst_lo;

        u64 *flowlabel = flowlabel_table.lookup(&ip6_hi);
        u64 *flowlabel2 = flowlabel_table.lookup(&ip6_lo);

        if (flowlabel && flowlabel2) 
        {
            bpf_trace_printk("%d\\n", *flowlabel);
            ip6->flow_label = *flowlabel;
        }

        //bpf_trace_printk("%d\\n", ip6->flow_label);
        //bpf_trace_printk("%d\\n", ip6->dst_hi);
        //bpf_trace_printk("%d\\n", ip6->dst_lo);
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
    try:
        b.trace_print()
    except KeyboardInterrupt:
        pass

    ipr.tc("del", "ingress", idx, "ffff:")
    ipr.tc("del", "sfq", idx, "1:")

print("BPF tc functionality - SCHED_CLS: OK")
