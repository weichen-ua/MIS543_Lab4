#!/bin/bash
cp -rf ./lab4_pox_firewall.py ~/pox/ext/
sudo ~/pox/pox.py forwarding.l3_learning --fakeways=192.168.1.1,10.0.0.1 lab4_pox_firewall info.packet_dump samples.pretty_log log.level --INFO
