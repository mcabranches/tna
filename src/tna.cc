#include "tna.h"

using namespace tna;

int stop = 0;


static void unload_prog(int sig) {
    std::cout <<"\nStopping TNA controller ..." <<  std::endl;
    //string del_fp = "rm src/*.bpf.*";
    //system(del_fp.c_str());
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

    //tnanl.init_tna_objects(&tnatm.tnaodb);
    tnanl.init_tna_objects(&tnatm);

    //TNA Tnabr object
    //Tnabr tnabr = Tnabr(XDP_FLAGS_SKB_MODE);
    //create_tna_bridge(&tnabr, &tnanl);

    //TNA Tnaipt object - does not use tnanl (Netlink)
    //Tnaipt tnaipt = Tnaipt();

    //string build_fp = "cd ../src && cd fp_assembler/fps && fps && cd .. && make";
    //system(build_fp.c_str());
    
    cout << "-----------------------" << endl;
    cout << "TNA main loop ..." << endl;
    cout << "-----------------------" << endl;
    
    tnatm.update_tna_topo();
    tnatm.tna_topo_print();
    tnatm.deploy_tnafp();

    while(!stop) { //controller's main loop
        cout << "..." << endl;
        //process_tna_event(&tnabr, &tnanl, &tnaipt);
        //this blocks and is awaken if an event happens
        process_tna_event(&tnanl, &tnatm);
    }

    return 0;
}
