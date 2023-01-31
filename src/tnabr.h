#ifndef TNABR_H
#define TNABR_H

#include "util.h"

class Tnabr {
	public:
		Tnabr(void)
		{
			cout << "Creating tnabr object" << endl;
		}

		~Tnabr(void) 
		{
			destroy_tnabr();
        }

		unordered_map<string, struct tna_bridge> tnabrs;

		int add_tna_bridge(struct tna_bridge tnabridge) 
		{
			tnabrs[tnabridge.brname] = tnabridge;
			tnabrs[tnabridge.brname].brifs.clear();

			cout << "Created tna bridge: " << tnabridge.brname << endl;

			return 0;
		}

		int del_tna_bridge(struct tna_bridge tnabridge)
		{	
			unordered_map<string, struct tna_interface *>::iterator it;

			for (it = tnabrs[tnabridge.brname].brifs.begin(); it != tnabrs[tnabridge.brname].brifs.end(); ++it) {
				tnabrs[tnabridge.brname].brifs[it->second->ifname]->ref_cnt -= 1;
			}

			tnabrs.erase(tnabridge.brname);

			cout << "Removed tna bridge: " << tnabridge.brname << endl;
		}

		int get_tna_bridges(void) 
		{
			unordered_map<string, struct tna_bridge>::iterator it;

			cout << "Available TNA bridges: " << endl;

			for (it = tnabrs.begin(); it != tnabrs.end(); ++it) {
				if (it->second.brname != "")
        			cout << it->first << endl;
			}

			return 0;
		}

		int add_if_tna_bridge(struct tna_bridge tnabridge, struct tna_interface *tnainterface) 
		{
			if (tnainterface->ifindex == tnainterface->master_index) {
				return -1;
			}

			if (tnabridge.brname.length() == 0)
				return -2;
				
			cout << "Adding interface " << tnainterface->ifname << " to TNA bridge " << tnabridge.brname << endl;
			cout << "Interface type: " << tnainterface->type << endl;

			tnabrs[tnabridge.brname].brifs[tnainterface->ifname] =  tnainterface; //push_back(tnainterface);
			tnabrs[tnabridge.brname].brifs[tnainterface->ifname]->xdp_set = 0;
			tnabrs[tnabridge.brname].brifs[tnainterface->ifname]->ref_cnt += 1;			

			update_br_ifs_info();
			tnabrs[tnabridge.brname].stp_enabled = get_stp_status(tnabridge.brname);

			return 0;
		}

		int remove_if_tna_bridge(struct tna_bridge tnabridge, struct tna_interface *tnainterface) 
		{
			if (tnabridge.brname.length() == 0)
				return -2;

			unordered_map<string, struct tna_interface *>::iterator it;

			cout << "Removing interface " << tnainterface->ifname << " from TNA bridge " << tnabridge.brname << endl;
			
			for (it = tnabrs[tnabridge.brname].brifs.begin(); it != tnabrs[tnabridge.brname].brifs.end(); ++it) {
        		if (it->second->ifname == tnainterface->ifname) {
					tnabrs[tnabridge.brname].brifs[tnainterface->ifname]->ref_cnt -= 1;
					tnabrs[tnabridge.brname].brifs.erase(it->first); //remove pointer
					break;
				}
			}

			return 0;
		}

		int get_br_tna_interfaces(string brname) 
		{
			unordered_map<string, struct tna_interface *>::iterator it;

			if (!(tnabrs.find(brname) == tnabrs.end())) {

				cout << "Available interfaces in TNA bridge " << tnabrs[brname].brname << endl;

				for (it = tnabrs[brname].brifs.begin(); it != tnabrs[brname].brifs.end(); ++it)
					cout << "ifname: " << it->second->ifname << endl;
			}

			return 0;
		}

		int destroy_tnabr(void) 
		{
			_destroy_tnabr();
			return 0;
		}

		int update_tna_bridge(struct tna_interface *interface)
		{

            struct tna_bridge tnabridge;
            char *br_name = NULL;
            int xdp_set;

            br_name = (char *)alloca(sizeof(char *) * IFNAMSIZ);

			update_br_ifs_info();

            if (interface->type == "bridge") {
                tnabridge.brname = interface->ifname;
                tnabridge.op_state = interface->op_state;
                tnabridge.op_state_str = interface->op_state_str;
				tnabridge.has_l3 = interface->has_l3;
				tnabridge.has_l3_br_dev = interface->has_l3;

                if (!(tnabrs.find(tnabridge.brname) == tnabrs.end())) {
                    cout << "bridge " << tnabridge.brname  << " exists updating state ..." << endl;
                    if_indextoname(interface->ifindex, br_name);
                    tnabrs[br_name].op_state_str = interface->op_state_str;
                    tnabridge.op_state = interface->op_state;
                    tnabridge.op_state_str = interface->op_state_str;
					tnabrs[br_name].stp_enabled = get_stp_status(br_name);
					tnabrs[br_name].has_l3 = interface->has_l3;
					tnabrs[br_name].has_l3_br_dev = interface->has_l3;
                }
                else {
                    add_tna_bridge(tnabridge);
                }
            }

            else if ((interface->type == "phys") || interface->type == "veth") {
                if_indextoname(interface->master_index, br_name);
                if (!(tnabrs[br_name].brifs.find(interface->ifname) == tnabrs[br_name].brifs.end())) {
					if (tnabrs[br_name].brname.length() == 0)
						return -2;
                    //cout << "Interface exists on bridge " << br_name << " updating state ..." << endl;
                    xdp_set = tnabrs[br_name].brifs[interface->ifname]->xdp_set;
                    tnabrs[br_name].brifs[interface->ifname] = interface;
                    tnabrs[br_name].brifs[interface->ifname]->xdp_set = xdp_set;
                }
                else if (interface->master_index > 1) {
                    	add_if_tna_bridge(tnabrs[br_name], interface);
                }
            }

			if (interface->tna_event_type == 2) {
				if (interface->type == "bridge") {
					del_tna_bridge(tnabridge);
				}

				else if (interface->type == "phys") {
					if (interface->master_index != 0) {
						remove_if_tna_bridge(tnabrs[br_name], tnabrs[br_name].brifs[interface->ifname]);
					}
				}
			}
			update_br_ifs_info();
		}

		int update_br_ifs_info(void)
		{
			unordered_map<string, struct tna_bridge>::iterator br_it;
            unordered_map<string, struct tna_interface *>::iterator if_it;
            unordered_map<int, struct tna_vlan>::iterator vlan_it;
			
			/* Verify vlans and tagging on deployed bridges -- this will customize the deployed XDP code */
            for (br_it = tnabrs.begin(); br_it != tnabrs.end(); ++br_it) {

                br_it->second.has_vlan = 0;
                br_it->second.has_untagged_vlan = 0;

				if (!br_it->second.has_l3_br_dev)
					br_it->second.has_l3 = 0; //reset l3 flag;

                for (if_it = br_it->second.brifs.begin(); if_it != br_it->second.brifs.end(); ++if_it) {

					//update L3 info for br interfaces
					if (br_it->second.brname.length() == 0)
						return -2;

					if (if_it->second->has_l3) {
						br_it->second.has_l3 = 1;
					}
                    
					//update VLAN info
                    for (vlan_it = if_it->second->vlans.begin(); vlan_it != if_it->second->vlans.end(); ++vlan_it) {
                        
                        if (vlan_it->second.vid > 1) {
                            br_it->second.has_vlan |= 1;
                            if (vlan_it->second.is_untagged_vlan == 1) {
                                br_it->second.has_untagged_vlan |= 1;
                            }
                            else {
                                br_it->second.has_untagged_vlan |= 0;
                            }

                        }
                        else {
                            br_it->second.has_vlan |= 0;
                                br_it->second.has_untagged_vlan |= 0;
                        }

                    }
                }
			}
		}

		static int get_stp_status(string br_name)
        {
            string br_conf_path;
            br_conf_path = "/sys/class/net/";
            br_conf_path.append(br_name);
            br_conf_path.append("/bridge/stp_state");
            ifstream ifs(br_conf_path);
            string stp_status((std::istreambuf_iterator<char>(ifs)),
                       (std::istreambuf_iterator<char>()));
			stp_status.pop_back(); //remove last character
            if (stp_status == "0")
                return 0;
            else
                return 1;
        }

	private:
		//implement clean up routine (if needed)
		int _destroy_tnabr(void)
		{
			cout << "Delete Tnabr" << endl;

			return 0;
		}

};
#endif