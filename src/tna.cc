#include "tna.h"

using namespace tna;

int stop = 0;


static void unload_prog(int sig) {
    std::cout <<"\nStopping TNA controller ..." <<  std::endl;
    stop = 1;
    tnanl_g_ns::clean_g_ns();
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

    //TNA Tnaipt opbject
    Tnaipt tnaipt = Tnaipt();

    std::cout <<"Starting TNA controller ..." <<  std::endl;

    while(!stop) { //controller's main loop
        std::cout << "-----------------------" << std::endl;
        std::cout << "TNA main loop ..." << std::endl;
        //this blocks and is awaken if an event happens
        process_tnanl_event(&tnabr, &tnanl);
        //if (tnaipt.has_unsupported_rule())
        //    cout << "Unsupported" << endl;

        //tnaipt.refresh_tnaipt();
        //sleep(1);
    }

    return 0;
}