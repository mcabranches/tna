#!/bin/bash

brctl addbr br0
brctl addif br0 enp0s8
brctl addif br0 enp0s9
ifconfig enp0s8 up
ifconfig enp0s9 up
ifconfig br0 up
brctl stp br0 on #may comment if not using STP