# TNA IPVS

This is just here temporarily, for development, until it's ready to become part of the accelerator library.

#### To Build:

Run make on the general TNA build
```bash
cd tna/src
make
```

Then build the ipvs bpf code:
```bash
cd tna/src/fp_assembler/tnaipvs
make
```

Instructions to install/remove the tc code:
```
sudo tc qdisc add dev ens1f1np1 clsact
sudo tc filter add dev ens1f1np1 ingress matchall action bpf object-file build/.output/tnaipvstc.bpf.o
sudo tc filter show dev ens1f1np1 ingress
sudo tc qdisc del dev ens1f1np1 clsact
sudo tc filter show dev ens1f1np1 ingress
```
