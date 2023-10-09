# CPU hotspots (TNA vs Linux vs PCN)

This directory has flamegraphs comparing CPU hotspots for each system running on just one core and forwarding as much traffic as possible in different use cases. The traffic was generated using DPDK's Pktgen on a directly connected machine with 2 10 Gbps NICs.

## Download Flamegraph

* git clone https://github.com/brendangregg/FlameGraph

## Generate perf.data

Run the desired workload and generate 'perf.data' using 'perf' (which can be compiled from Linux the Linux sources the 'tools/' folder.

Go to the perf directory and run:

* ./perf record -F 99 -a -g -- sleep 60

Generate the flamegraphs

* ./perf script | /data/FlameGraph/stackcollapse-perf.pl |/data/FlameGraph/flamegraph.pl > /dst_dir/flame.svg
