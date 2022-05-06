#include "tna.h"

using namespace tna;

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

    //TNA NetLink object
    Tnanl tnanl = Tnanl();

    //TNA Tnabr object
    Tnabr tnabr = Tnabr(XDP_FLAGS_SKB_MODE);
    //tnanl.dump_cached_interfaces();
    create_tna_bridge(tnabr, tnanl);

    std::cout <<"Starting TNA controller ..." <<  std::endl;

    while(!stop) { //controller's main loop
        sleep(1);
    }

    return 0;
}