This repository contains code for editing the flow labels of IPv6 packets using ebpf. It requires the package python3-bcc (available on RHEL8 derivatives and later), and the python package pyroute2. 

When flowlabel_two.py is run, it puts ingress and egress ebpf filters on the loopback interface. The ingress filter reads the flow label, although it currently doesn't do anything with it. The egress filter sets the flow label to a currently hard-coded value, and then prints it out. Flowlabel_two.py will run infinitely until it gets a ctrl-C, at which point it will print out a message for each IPv6 packet sent by the loopback interface.

Flowlabel_betteroutput.py is a later version, which doesn't use trace_print for output. Functionally it is the same as flowlabel_two.py, except that it runs for ten seconds instead of until ctrl-C. At the end, it prints out the number of IPv6 packets received, their flowlabels, and the flowlabels that were applied to the packets sent, if any.
