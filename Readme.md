# xdp-tna

Please download and install the kernel below

https://github.com/mcabranches/linux.git. Please add BTF support. Iptables should not be added as a module.

## Install dependencies

    sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential libnl-3-200 libnl-3-dev libnl-route-3-200 libnl-route-3-dev libiptc-dev libxtables-dev libboost-all-dev pkg-config python3-jinja2

## Compilation

    cd src/
    make
## Directory description

* src/ -> source code
* build -> binaries (./build/tna -> runs the TNA agent)
