/* TNA's topology manager */

#ifndef TNATM_H
#define TNATM_H

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>
#include <sstream>

#include "tnabr.h"
#include "tnafpd.h"

#define MAX_INTERFACES 32

class Tnatm {
    public:
        Tnatm(void)
        {
            cout << "Initializing Topology Manager" << endl;
        }

        ~Tnatm(void)
        {
            tnafpd.clean_tnafp(&tnaodb);
        }


        //TNA's object database
        Tnaodb tnaodb;
        boost::property_tree::ptree tna_topo;
        boost::property_tree::ptree prev_tna_topo;

        void add_tnabr(Tnabr *tnabr) 
        {
            cout << "Adding tnabr object to tnaodb" << endl;
            tnaodb.tnabr = tnabr;
        }

        int update_tna_topo(void) 
        {
            return _update_tna_topo();
        }

        bool tna_topo_changed(void)
        {
            return _tna_topo_changed();
        }

        void tna_topo_print(void)
        {
            std::stringstream cur_topo;
            boost::property_tree::json_parser::write_json(cur_topo, tna_topo);
            cout << cur_topo.str() << endl;
        }

        void create_tna_object(struct tna_interface *interfaces) //array
        {
            int master_index;
            for (int i = 0; i < MAX_INTERFACES; i++) {
                if (interfaces[i].type == "bridge") {
                    //cout << "Found bridge: " << interfaces[i].ifname << endl;
                    master_index = interfaces[i].ifindex;
                    struct tna_bridge tnabridge;
                    tnabridge.brname = interfaces[i].ifname;
                    tnabridge.op_state = interfaces[i].op_state;
                    tnabridge.op_state_str = interfaces[i].op_state_str;
                    tnaodb.tnabr->add_tna_bridge(tnabridge);

                    for (int i = 0; i < MAX_INTERFACES; i++) {
                         if (interfaces[i].master_index == master_index) {
                            interfaces[i].xdp_set = 0;
                            if (interfaces[i].type == "Null")
                                interfaces[i].type = "phys";
                            
                            tnaodb.tnaifs[interfaces[i].ifname] = interfaces[i];
                            tnaodb.tnabr->add_if_tna_bridge(tnabridge, &tnaodb.tnaifs[interfaces[i].ifname]);
                         }
                    }
                }
            }
        }

        int deploy_tnafp(void)
        {
            cout << "Updating TNA fast path" << endl;
            tnafpd.deploy_tnafp(&tnaodb);
            return 0; 
        }

    private:
        Tnafpd tnafpd = Tnafpd();
        hash<string> get_hash;
        list<string> fpms, cfg;

        int _update_tna_topo(void)
		{
			cout << "Updating TNA topology" << endl;
            prev_tna_topo = tna_topo;
            tna_topo.clear();

            unordered_map<string, struct tna_bridge>::iterator br_it;
            unordered_map<string, struct tna_interface>::iterator if_it;

            fpms.clear();

            //process bridges
            for (br_it = tnaodb.tnabr->tnabrs.begin(); br_it != tnaodb.tnabr->tnabrs.end(); ++br_it) {
                if (br_it->second.brname != "") {
                    cout << "Adding bridge to tna_topo: " << br_it->second.brname << endl;
                    fpms.push_back("tnabr");
                    tna_topo_add_br_config(br_it->second);
                }
            }

            //process interfaces
            for (if_it = tnaodb.tnaifs.begin(); if_it != tnaodb.tnaifs.end(); ++if_it) {
                if (if_it->second.ref_cnt < 1) {
                    tnafpd.uninstall_tnafp(&if_it->second);
                    tnaodb.tnaifs.erase(if_it->first);
                }
            }

            tna_topo_add_fpm();
            tna_topo_add_interfaces();
            
            return 0;
		}

        void tna_topo_add_fpm(void)
        {
            list<string>::iterator it;
            boost::property_tree::ptree elements;
            boost::property_tree::ptree child;

            for (it = fpms.begin(); it != fpms.end(); ++it) {
                elements.put_value(*it);
                child.push_back(make_pair("",elements));
            }

            tna_topo.put_child("fpms", child);
        }

        void tna_topo_add_interfaces(void)
        {
            unordered_map<string, struct tna_interface>::iterator it;
            boost::property_tree::ptree elements;
            boost::property_tree::ptree child;

            for (it = tnaodb.tnaifs.begin(); it != tnaodb.tnaifs.end(); ++it) {
                elements.put_value(it->first);
                child.push_back(make_pair("",elements));
            }
            tna_topo.put_child("interfaces", child);            

        }

        void tna_topo_add_br_config(struct tna_bridge tnabridge)
        {
            unordered_map<string, struct tna_interface *>::iterator it;
            boost::property_tree::ptree elements;
            boost::property_tree::ptree subtree;

            string property_path;
            string property_path_child;

            property_path = "config.tnabr.brname";
            tna_topo.put(property_path, tnabridge.brname);

            property_path = "config.tnabr.has_vlan";
            tna_topo.put(property_path, tnabridge.has_vlan);

            property_path = "config.tnabr.stp_enabled";
            tna_topo.put(property_path, tnabridge.stp_enabled);

            property_path = "config.tnabr.interfaces";

            for (it = tnabridge.brifs.begin(); it != tnabridge.brifs.end(); ++it) {
                property_path_child.erase();
                property_path_child.append("name");
                elements.put(property_path_child, it->second->ifname);
                property_path_child.erase();
                property_path_child.append("op_state");
                elements.put(property_path_child, it->second->op_state_str);
                property_path_child.erase();
                property_path_child.append("type");
                elements.put(property_path_child, it->second->type);
                subtree.push_back(make_pair("",elements));
            }
            tna_topo.add_child(property_path, subtree);
        }

        bool _tna_topo_changed(void)
        {
            bool changed = false;
            std::stringstream cur_topo;
            std::stringstream prev_topo;

            boost::property_tree::json_parser::write_json(cur_topo, tna_topo);
            boost::property_tree::json_parser::write_json(prev_topo, prev_tna_topo);

            if ((get_hash(cur_topo.str())) != (get_hash(prev_topo.str()))){
                changed = true;
            }

            return changed;
        }
};
#endif
