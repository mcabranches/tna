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
    cout << "\n#### TNA ####\n\n";
    cout <<"\nStarting TNA controller ...\n\n";

    signal(SIGINT, unload_prog);
    signal(SIGTERM, unload_prog);

    Tnanl tnanl = Tnanl();
    Tnatm tnatm = Tnatm();

    Tnabr tnabr = Tnabr();
    tnatm.add_tnabr(&tnabr);

    Tnartr tnartr = Tnartr();
    tnatm.add_tnartr(&tnartr);

    Tnaipt tnaipt = Tnaipt();
    tnatm.add_tnaipt(&tnaipt);

    tnanl.init_tna_objects(&tnatm);
    
    cout << "-----------------------" << endl;
    cout << "TNA main loop ..." << endl;
    cout << "-----------------------" << endl;
    
    tnatm.update_tna_topo();
    tnatm.tna_topo_print();
    tnatm.deploy_tnafp();

    /* controller's main loop */
    while(!stop) {
        cout << "..." << endl;
        /* this blocks and is awaken if an event happens */
        process_tna_event(&tnanl, &tnatm);
    }

    return 0;
}
