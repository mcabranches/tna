#include "tna.h"

using namespace tna;

int stop = 0;


static void unload_prog(int sig) {
    std::cout <<"\nStopping TNA controller ..." <<  std::endl;
    stop = 1;
    tna_g_ns::clean_g_ns();
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
    create_tna_bridge(&tnabr, &tnanl);

    //TNA Tnaipt object - does not use tnanl (Netlink)
    Tnaipt tnaipt = Tnaipt();

    std::cout <<"Starting TNA controller ..." <<  std::endl;

    std::cout << "-----------------------" << std::endl;
    std::cout << "TNA main loop ..." << std::endl;
    std::cout << "-----------------------" << std::endl;
    while(!stop) { //controller's main loop
        //this blocks and is awaken if an event happens
        cout << "..." << endl;
        //process_tna_event(&tnabr, &tnanl, &tnaipt);
        process_tna_event(&tnabr, &tnanl, NULL);
    }

    return 0;
}
