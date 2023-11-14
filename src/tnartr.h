#ifndef TNARTR_H
#define TNARTR_H

#include "util.h"

class Tnartr {
    public:
        Tnartr(void)
        {
            cout << "Creating tnartr object" << endl;
            tnartr.rtrifs.clear();
            num_interfaces = 0;
        }

        ~Tnartr(void)
        {
            destroy_tnartr();
        }

        int destroy_tnartr(void)
        {
            _destroy_tnartr();
            return 0;
        }

        struct tna_rtr tnartr; //just one per box
        int num_interfaces;

        // int add_tna_rtr(struct tna_rtr tnartr) 
		// {
		// 	tnartrs[num_rtrs] = tnartr;
		// 	//tnabrs[tnabridge.brname].brifs.clear();

		// 	cout << "Created tna rtr: " << endl;

		// 	return 0;
		// }

        int update_tna_rtr(struct tna_interface *interface)
        {
            if (interface->has_l3 && get_fwd_status()) {
                cout << "Updating tnartr" << endl;
                cout << "interface->ifname " <<  interface->ifname << endl;
                tnartr.rtrifs[interface->ifname] = interface;
            }

            return 0;
        }
    
    private:
        //implement clean up routine (if needed)

        int _destroy_tnartr(void) 
        {
            cout << "Delete Tnartr" << endl;

            return 0;
        }

        int get_fwd_status(void) 
        {
            string fwd_status_path;
            fwd_status_path = "/proc/sys/net/ipv4/ip_forward";
            ifstream ifs(fwd_status_path);
            string fwd_status((std::istreambuf_iterator<char>(ifs)),
                       (std::istreambuf_iterator<char>()));
            fwd_status.pop_back();
            if (fwd_status == "0")
                return 0;
            else
                return 1;
        }

};
#endif