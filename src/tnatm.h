/* TNA's topology manager */

#ifndef TNATM_H
#define TNATM_H

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>
#include <sstream>

#include "tnabr.h"
#include "tnartr.h"
#include "tnaipt.h"
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
            fpms["tnabr"] = tnabr_fpm;
        }

        void add_tnartr(Tnartr *tnartr)
        {
            cout << "Adding tnartr object to tnaodb" << endl;
            tnaodb.tnartr = tnartr;
            fpms["tnartr"] = tnartr_fpm;
        }

        void add_tnaipt(Tnaipt *tnaipt)
        {
            cout << "Adding tnaipt object to tnaodb" << endl;
            tnaodb.tnaipt = tnaipt;
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
                if (ignore_ifs(interfaces[i])) {
                    continue;
                }
                if (interfaces[i].type == "bridge") {
                    //cout << "Found bridge: " << interfaces[i].ifname << endl;
                    master_index = interfaces[i].ifindex;
                    struct tna_bridge tnabridge;
                    tnabridge.brname = interfaces[i].ifname;
                    tnabridge.op_state = interfaces[i].op_state;
                    tnabridge.op_state_str = interfaces[i].op_state_str;
                    tnabridge.stp_enabled = 0;
                    tnabridge.has_l3_br_dev = interfaces[i].has_l3;
                    tnabridge.has_l3 = interfaces[i].has_l3; 
                    tnaodb.tnaifs[interfaces[i].ifname] = interfaces[i];
                    tnaodb.tnabr->add_tna_bridge(tnabridge);

                    if (tnabridge.has_l3)
                        if (tnaodb.tnaipt->has_ipt())
                            tnabridge.has_ipt = 1;


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
                else {
                   interfaces[i].xdp_set = 0;
                    if (interfaces[i].type == "Null")
                        interfaces[i].type = "phys";
                    tnaodb.tnaifs[interfaces[i].ifname] = interfaces[i];
                    tnaodb.tnartr->update_tna_rtr(&tnaodb.tnaifs[interfaces[i].ifname]);
                    //cout << "interfaces[i].ifname: " << interfaces[i].ifname << endl;
                    //cout << "interfaces[i].has_l3: " << interfaces[i].has_l3 << endl;

                }
            }
        }

        bool ignore_ifs(struct tna_interface interface) 
        {
            if(tnaodb.ignore_ifs.find(interface.ifname) != tnaodb.ignore_ifs.end())
                return true;
            else 
                return false;
            //return 0;
        }

        int deploy_tnafp(void)
        {
            cout << "Updating TNA fast path" << endl;
            //30/11/2023 - make this go through bridges, routers, and ipvs
            //If they have interfaces, do call_tnafpa(tnafpm) and then 
            //call tnafpd.deploy_tnafp(&tnaodb)
            //tnafpd.deploy_tnafp(&tnaodb) should be changed to process the different fast paths 
            //ex: get each br or rtr, iterate on their interfaces and install the fp 
            //maybe create one deployer for each fp and only call them when needed 
            //if (tnaodb.tnartr->tnartr.rtrifs.count() > 1) {
                call_tnafpa("tnartr");
                tnafpd.deploy_tnafp(&tnaodb);
            //}
            return 0; 
        }

    private:
        Tnafpd tnafpd = Tnafpd();
        hash<string> get_hash;
        //list<string> fpms, cfg;
        list<string> cfg, tnabr_fpm, tnartr_fpm;
        unordered_map<string, list<string>> fpms;

        int _update_tna_topo(void)
		{
			cout << "Updating TNA topology" << endl;
            prev_tna_topo = tna_topo;
            tna_topo.clear();

            tna_interface interface;
            unordered_map<string, struct tna_bridge>::iterator br_it;
            unordered_map<string, struct tna_interface>::iterator if_it;
            unordered_map<string, struct tna_interface *>::iterator rtrif_it;

            fpms["tnabr"].clear();
            fpms["tnartr"].clear();

            //process bridges
            for (br_it = tnaodb.tnabr->tnabrs.begin(); br_it != tnaodb.tnabr->tnabrs.end(); ++br_it) {
                if (br_it->second.brname != "") {
                    //cout << "Adding bridge to tna_topo: " << br_it->second.brname << endl;
                    fpms["tnabr"].push_back("tnabr");

                    if (br_it->second.has_l3) {
                        fpms["tnabr"].push_back("tnartr");
                        if (tnaodb.tnaipt->has_ipt()) {
                            br_it->second.has_ipt = 1;
                            fpms["tnabr"].push_back("tnaipt");
                        }
                    }
                        
                    tna_topo_add_br_config(br_it->second);
                }
            }

            //process router
            for (rtrif_it = tnaodb.tnartr->tnartr.rtrifs.begin(); rtrif_it != tnaodb.tnartr->tnartr.rtrifs.end(); ++rtrif_it) {
                fpms["tnartr"].push_back("tnartr");
                tna_topo_add_rtr_config(tnaodb.tnartr->tnartr); //implement
            }

            //process interfaces
            for (if_it = tnaodb.tnaifs.begin(); if_it != tnaodb.tnaifs.end(); ++if_it) {
                if (if_it->second.ref_cnt == 0) {
                    tnafpd.uninstall_tnafp(&if_it->second);
                }
            }

            //tna_topo_add_fpm();
            //tna_topo_add_interfaces();
            
            return 0;
		}


        void tna_topo_add_fpm(void)
        {
            list<string>::iterator it;
            boost::property_tree::ptree elements;
            boost::property_tree::ptree child;
            string parent = "fpms";

            //process tnabr
            for (it = fpms["tnabr"].begin(); it != fpms["tnabr"].end(); ++it) {
                elements.put_value(*it);
                child.push_back(make_pair("",elements));
                cout << "elements "<< elements.data() << endl;
                tna_topo.put_child(parent, child);
                parent = it->c_str();
            }

            elements.clear();
            child.clear();
            
            //process tnartr
            for (it = fpms["tnartr"].begin(); it != fpms["tnartr"].end(); ++it) {
                elements.put_value(*it);
                child.push_back(make_pair("",elements));
                tna_topo.put_child(parent, child);
                parent = it->c_str();
            }
        }

        void tna_topo_add_interfaces(void)
        {
            unordered_map<string, struct tna_interface>::iterator it;
            boost::property_tree::ptree elements;
            boost::property_tree::ptree child;

            for (it = tnaodb.tnaifs.begin(); it != tnaodb.tnaifs.end(); ++it) {
                if (it->second.ref_cnt > 0) {
                    elements.put_value(it->first);
                    child.push_back(make_pair("",elements));
                }
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

            property_path = "config.tnabr.has_l3";
            tna_topo.put(property_path, tnabridge.has_l3);

            property_path = "config.tnabr.has_ipt";
            tna_topo.put(property_path, tnabridge.has_ipt);

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

        void tna_topo_add_rtr_config(struct tna_rtr tnartr)
        {
            unordered_map<string, struct tna_interface *>::iterator it;
            boost::property_tree::ptree elements;
            boost::property_tree::ptree subtree;

            string property_path;
            string property_path_child;

            property_path = "config.tnartr.rtrname";
            tna_topo.put(property_path, "tnartr1");

            property_path = "config.tnartr.ipv4_fwd_enabled";
            tna_topo.put(property_path, "1");

            property_path = "config.tnartr.has_tnabr"; //get this from tnaodb on "update_rtr"
            tna_topo.put(property_path, "1");

            property_path = "config.tnartr.has_ipt";
            tna_topo.put(property_path, "0");

            property_path = "config.tnartr.interfaces";

            for (it = tnartr.rtrifs.begin(); it != tnartr.rtrifs.end(); ++it) {
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

        int call_tnafpa(std::string fpm)
        {
            std::stringstream ss;
            std::string pycmd;

            boost::property_tree::json_parser::write_json(ss, tna_topo);

            pycmd = "cd ./src/fp_assembler && python3 tnasynth.py " + fpm + " '" + ss.str() + "'";

            cout << pycmd << endl;

            system(pycmd.c_str());

            return 0;
        }
};
#endif
