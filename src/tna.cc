#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <linux/if_link.h>
#include "tnabr.h"

int stop = 0;

static void unload_prog(int sig) {
    std::cout <<"\nStopping TNA controller ..." <<  std::endl;
    stop = 1;
    return;
}

int main(void)
{
    
    signal(SIGINT, unload_prog);
	signal(SIGTERM, unload_prog);

    struct tna_bridge tnabridge;
    struct tna_interface tnainterface;
    auto tnabr = Tnabr();

    tnabridge.brname = "br0";
    tnabr.add_tna_bridge(tnabridge);
    //tnabridge.brname = "br1";
    //tnabr.add_tna_bridge(tnabridge);
    tnabr.get_tna_bridges();
    tnainterface.ifindex = 3;
    tnainterface.ifname = "enp0s3";
    tnabr.add_if_tna_bridge(tnabridge, tnainterface);
    tnainterface.ifindex = 4;
    tnainterface.ifname = "enp0s4";
    tnabr.add_if_tna_bridge(tnabridge, tnainterface);
    tnabr.get_br_tna_interfaces(tnabridge);
    tnabr.accel_tna_bridge(tnabridge);
    //tnabr.destroy_tnabr();

    //tnabr.install_tnabr(3);
    std::cout <<"Starting TNA controller ..." <<  std::endl;

    while(!stop) { //controller's main loop
        sleep(1);
    }

    return 0;
}