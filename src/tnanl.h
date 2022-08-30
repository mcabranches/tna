#ifndef TNANL_H
#define TNANL_H
/* steps using libnl

> create socket - struct nl_sock *nl_socket_alloc(void)
> subscribe to multicast group - int nl_socket_add_memberships(struct nl_sock *sk, int group, ...);
> define call back (cb) funtion to be called on receiving successful notifications ... static int my_func(...)
> modify default cb function for the socket - nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, my_func, NULL);
> set the socket nonblocking - int nl_socket_set_nonblocking(const struct nl_sock *sk);
> use poll (epoll) to periodically query new messages
> unsubscribe to multicast group - int nl_socket_drop_memberships(struct nl_sock *sk, int group, ...);
> free socket -  void nl_socket_free(struct nl_sock *sk)

*/
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/vlan.h>
#include <netlink/route/addr.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/neightbl.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter.h>
#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h> 
#include "util.h"

#define MAX_INTERFACES 32

class Tnanl {

    public:
        Tnanl(void) 
        {
            connect_nlr_q();
            build_link_nl_cache();
            add_membership_nlr();
            pthread_create(&t1_tnanl, NULL, tna_mon_nl, nlr_g_sk);
        }

       ~Tnanl(void) 
       {
            close_nlr_q();
            drop_membership_nlr();
            pthread_cond_destroy(&tna_g_ns::cv1);
            pthread_mutex_destroy(&tna_g_ns::m1);
       }

        void dump_cached_interfaces(void)
        {
            struct tna_interface interfaces[MAX_INTERFACES] = { 0 };
            nl_cache_foreach(link_nl_cache, link_cache_cb, &interfaces);
            cout << "Dumping cached interfaces" << endl;
            cout << "----------------" << endl;
            cout << "Index, Name, MAC, Status, Type, Master" << endl;
            for (int i = 0; i < MAX_INTERFACES; i++) {
                if (interfaces[i].ifindex != 0) {
                    cout << "----------------" << endl;
                    cout << interfaces[i].ifindex << ", " << interfaces[i].ifname << ", ";
                    cout << interfaces[i].mac_addr_str << ", ";
                    cout << interfaces[i].op_state_str << ", " << interfaces[i].type << ", ";
                    cout << interfaces[i].master_index << endl;
                }
            }
            cout << "----------------" << endl << endl;

            return;
        }

        void create_tna_bridge(Tnabr *tnabr)
        {
            int master_index;
            struct tna_interface interfaces[MAX_INTERFACES] = { 0 };
            nl_cache_foreach(link_nl_cache, link_cache_cb, &interfaces);

            for (int i = 0; i < MAX_INTERFACES; i++) {
                if (interfaces[i].type == "bridge") {
                    cout << "Found bridge: " << interfaces[i].ifname << endl;
                    master_index = interfaces[i].ifindex;
                    struct tna_bridge tnabridge;
                    tnabridge.brname = interfaces[i].ifname;
                    tnabridge.op_state = interfaces[i].op_state;
                    tnabridge.op_state_str = interfaces[i].op_state_str;
                    tnabr->add_tna_bridge(tnabridge);

                    for (int i = 0; i < MAX_INTERFACES; i++) {
                         if (interfaces[i].master_index == master_index) {
                            tnabr->add_if_tna_bridge(tnabridge, interfaces[i]);
                         }
                    }
                    tnabr->accel_tna_bridge(tnabridge); //move this to tna.h   
                }
            }
        }


        void update_tna_bridge(Tnabr *tnabr, struct tna_interface interface, int event_type)
        {
            unordered_map<string, struct tna_bridge>::iterator br_it;
            unordered_map<string, struct tna_interface>::iterator if_it;
            unordered_map<int, struct tna_vlan>::iterator vlan_it;

            struct tna_bridge tnabridge;
            char *br_name;

            if (interface.type == "bridge") {
                tnabridge.brname = interface.ifname;
                tnabr->tnabrs[interface.ifname].op_state_str = interface.op_state_str;
            }
            else {
                br_name = (char *)alloca(sizeof(char *) * IFNAMSIZ);
                if_indextoname(interface.master_index, br_name);

                tnabr->tnabrs[br_name].brifs[interface.ifname].op_state_str = interface.op_state_str;;
            }

            //cout << "\n\nEVENT_TYPE: " << event_type << endl;
            //cout << "n_ifname: " << interface.ifname << endl;
            //cout << "ifindex: " << interface.ifindex << endl;
            //cout << "master_index: " << interface.master_index << endl;
            //cout << "n_type: " << interface.type << endl;
            //cout << "n_opstate: " << interface.op_state_str << endl << endl;

            if (event_type == 1) {

                if (interface.type == "bridge") {
                    tnabr->tnabrs[interface.ifname].op_state_str = interface.op_state_str;
                    tnabridge.brname = interface.ifname;

                    if (tnabr->tnabrs[interface.ifname].brname == interface.ifname) {

                        if (interface.op_state_str == "up") {

                            for (if_it = tnabr->tnabrs[interface.ifname].brifs.begin(); if_it != tnabr->tnabrs[interface.ifname].brifs.end(); ++if_it) {
                                if (if_it->second.op_state_str == "up")
					                tnabr->install_xdp_tnabr(if_it->second);
				            }

                        }

                    }
                    else {
                        tnabr->add_tna_bridge(tnabridge);
                    }

                    if (interface.op_state_str == "up") {
                        tnabr->accel_tna_bridge(tnabridge);
                    }

                }
                if (interface.type == "Null") {
                    if (interface.master_index != 0) {
                        int ifs_exists = 0;
                        char *br_name = (char *)alloca(sizeof(char *) * IFNAMSIZ);;
                        if_indextoname(interface.master_index, br_name);

                        for (if_it = tnabr->tnabrs[br_name].brifs.begin(); if_it != tnabr->tnabrs[br_name].brifs.end(); ++if_it) {
                                if (if_it->second.ifindex == interface.ifindex) {
                                    ifs_exists = 1;
                                    if (interface.op_state_str == "down")
                                        tnabr->uninstall_xdp_tnabr(interface);        

                                    break;
                                }
				        }
                        if (ifs_exists == 0) {
                            if (br_name) {
                                tnabridge.brname = br_name;
                                tnabr->add_if_tna_bridge(tnabridge, interface);
                                
                                if (tnabr->tnabrs[br_name].op_state_str == "up")
                                    tnabr->install_xdp_tnabr(interface);
                            }
                        }

                    }

                }

            }
            if (event_type == 2) {
                if (interface.type == "bridge") {

                }

                if (interface.type == "Null") {
                    if (interface.master_index != 0) {
                        tnabridge.brname = br_name;
                        tnabr->remove_if_tna_bridge(tnabridge, interface);
                    }

                }

            }
            if (event_type == 3) {
                if (interface.op_state_str == "down") {
                    for (if_it = tnabr->tnabrs[interface.ifname].brifs.begin(); if_it != tnabr->tnabrs[interface.ifname].brifs.end(); ++if_it) {
					    tnabr->uninstall_xdp_tnabr(if_it->second);
				    }
                }
            }
            if (event_type == 4) {
                tnabr->install_xdp_tnabr(interface);
            }

            if (event_type == 5) {

                /* Update vlan state */
                tnabr->tnabrs[br_name].brifs[interface.ifname].vlans = interface.vlans;

                /* Verify vlans and tagging on deployed bridges -- this will custmize the deployed XDP code */
                for (br_it = tnabr->tnabrs.begin(); br_it != tnabr->tnabrs.end(); ++br_it) {
                    br_it->second.has_vlan = 0;
                    br_it->second.has_untagged_vlan = 0;

                    for (if_it = br_it->second.brifs.begin(); if_it != br_it->second.brifs.end(); ++if_it) {
                    
                        for (vlan_it = if_it->second.vlans.begin(); vlan_it != if_it->second.vlans.end(); ++vlan_it) {
                        
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

                    if (br_it->second.brname != "") {
                        if (br_it->second.has_vlan) {
                            cout << "Detected VLAN on BR: " << br_it->second.brname << endl;
                            if (br_it->second.has_untagged_vlan) {
                                cout << "Detected untagged VLAN on BR: " << br_it->second.brname << endl;
                            }
                        }
                        else {
                            cout << "No VLANs were detected on BR " << br_it->second.brname << endl;
                        }

                    }
                }
            }
        }


    private:
        struct nl_sock *nlr_q_sk; //cache query nl route socket
        struct nl_sock *nlr_g_sk; //multicast group nl route socket
        struct nl_cache *link_nl_cache;
        pthread_t t1_tnanl;
       
        int connect_nlr_q(void) 
        {
            cout << "Connecting to NETLINK_ROUTE socket ..." << endl; 

            nlr_q_sk = nl_socket_alloc();
            nl_connect(nlr_q_sk, NETLINK_ROUTE);

            return 0;
        }

        int close_nlr_q(void)
        {
            cout << "Closing NETLINK_ROUTE socket" << endl;

            nl_socket_free(nlr_q_sk);

            return 0;
        }

        static int nlr_g_cb(struct nl_msg *msg, void *arg)
        {
            //cout << "Received NETLINK_ROUTE event" << endl;
    
            struct nlmsghdr* nlh = nlmsg_hdr(msg);
            struct ifinfomsg* if_info = (struct ifinfomsg*) (nlmsg_data(nlh));
            struct bridge_vlan_info *vinfo;
            struct tna_interface ifs_entry = { 0 };
            int event_type = 0;

            struct nlattr *attrs[IFLA_MAX+1];

            ifs_entry.ifindex = if_info->ifi_index;
            ifs_entry.type = "Null";
            
            if (nlmsg_parse(nlh, sizeof(struct nlmsghdr), attrs, IFLA_MAX, rtln_link_policy) < 0) {
                /* error */
                cout << "Error parsing NL attributes\n";            
            }

            if (attrs[IFLA_IFNAME]) {
                ifs_entry.ifname = nla_get_string(attrs[IFLA_IFNAME]);
            }

            if (attrs[IFLA_MASTER]) {
                ifs_entry.master_index = nla_get_u32(attrs[IFLA_MASTER]);
            }

            if (attrs[IFLA_OPERSTATE]) {
                char op_state_c[32];
                ifs_entry.op_state = nla_get_u32(attrs[IFLA_OPERSTATE]);
                rtnl_link_operstate2str(ifs_entry.op_state, op_state_c, sizeof(op_state_c));
                ifs_entry.op_state_str = op_state_c;
            }


            if (attrs[IFLA_LINKINFO]) {
                struct nlattr *li[IFLA_INFO_MAX+1];

                if (nla_parse_nested(li, IFLA_INFO_MAX, attrs[IFLA_LINKINFO], rtln_link_policy) < 0) {
                    /* error */
                    cout << "Error parsing nested NL attributes\n";  
                }
                if (li[IFLA_INFO_KIND]) {
                    char *kind = nla_get_string(li[IFLA_INFO_KIND]);
                    if (kind) 
                        ifs_entry.type = kind;
                }
            }

            if (attrs[IFLA_AF_SPEC]) {
                struct nlattr *af_attr;
                int remaining;

                nla_for_each_nested(af_attr, attrs[IFLA_AF_SPEC], remaining) {
                    if (af_attr->nla_type == IFLA_BRIDGE_VLAN_INFO) {
                        vinfo = (struct bridge_vlan_info *) nla_data(af_attr);
                        if (vinfo->vid > 1) {
                            /* build a list of active VLANs on an interface */
                            ifs_entry.vlans[vinfo->vid].vid = vinfo->vid;
                            if (vinfo->flags & BRIDGE_VLAN_INFO_UNTAGGED) {
                                ifs_entry.vlans[vinfo->vid].is_untagged_vlan = 1;
                            }
                            else {
                                ifs_entry.vlans[vinfo->vid].is_untagged_vlan = 0;
                            }
                        }
                    }
                }
            }

            //if (attrs[IFLA_AF_SPEC]) {
            //    ifs_entry.xdp_set = 1;
            //}

            //cout << "family: " << if_info->ifi_family << endl;
            //cout << "type: " << if_info->ifi_type << endl;
            //cout << "\nifi_change: " << if_info->ifi_change << endl;
            //cout << "ifi_flags " << if_info->ifi_flags << endl;

            //cout << "MSG_TYPE: " << (int) nlh->nlmsg_type << endl;
            //cout << "ifname: " << ifs_entry.ifname << endl;
            //cout << "vid: " << ifs_entry.cur_vlan.vid << endl;
            //cout << "has_untagged_vlan: " << ifs_entry.cur_vlan.is_untagged_vlan << endl;
            

            if (((int) nlh->nlmsg_type == RTM_NEWLINK) && (ifs_entry.type == "bridge") && (if_info->ifi_change == 0)) {
                event_type = 1;
            }
            
            if (((int) nlh->nlmsg_type == RTM_NEWLINK) && (ifs_entry.type == "Null") && (if_info->ifi_change > 0)) {
                if ((if_info->ifi_flags & IFF_UP) && if_info->ifi_change != 256 ) {
                        event_type = 4;
                }
                else {
                    event_type = 1;
                }
            }

            if ((int) nlh->nlmsg_type == RTM_DELLINK) {
                event_type = 2;
            }

            if (((int) nlh->nlmsg_type == RTM_NEWLINK) && (ifs_entry.type == "bridge") && (if_info->ifi_change == 1)) {
                if (!(if_info->ifi_flags & IFF_UP)) {
                    event_type = 3;
                }
            }
            /* event type 5 -> update vlan state */
            //else
            //    event_type = 5; 

            if (((int) nlh->nlmsg_type == RTM_NEWLINK) && (ifs_entry.type == "Null") && (if_info->ifi_change == 0)) {
                event_type = 5;
            }

            pthread_mutex_lock(&tna_g_ns::m1);

            tna_g_ns::tna_event_type = event_type;

            tna_g_ns::tna_event_flag = tna_g_ns::TNA_BR_EVENT;

            tna_g_ns::interface_g = ifs_entry;
            
            pthread_cond_signal(&tna_g_ns::cv1);
            pthread_mutex_unlock(&tna_g_ns::m1);
            
            return 0;
        }

        int add_membership_nlr(void)
        {
            cout << "Adding NETLINK_ROUTE multicast membership" << endl;
            
            nlr_g_sk = nl_socket_alloc();
            nl_socket_disable_seq_check(nlr_g_sk);
            nl_socket_modify_cb(nlr_g_sk, NL_CB_VALID, NL_CB_CUSTOM, nlr_g_cb, NULL);
            nl_connect(nlr_g_sk, NETLINK_ROUTE);
            nl_socket_add_memberships(nlr_g_sk, RTNLGRP_LINK, 0);

            return 0;
        }

        int drop_membership_nlr(void)
        {
            cout << "Dropping NETLINK_ROUTE multicast membership" << endl;

            nl_socket_drop_memberships(nlr_g_sk, RTNLGRP_LINK, 0);
            nl_socket_free(nlr_g_sk);

            return 0;
        }

        int build_link_nl_cache(void)
        {
            cout << "\nBuilding rtnl_cache ..." << endl;

            if (rtnl_link_alloc_cache(nlr_q_sk, AF_UNSPEC, &link_nl_cache) < 0)
                cout << "Error building link rtnl_cache ..." << endl;

            return 0;
        }

        static void link_cache_cb(struct nl_object *nl_object, void *interfaces)
        {
            struct rtnl_link *rtnl_link = (struct rtnl_link *)nl_object;
            struct nl_addr *nl_addr;
            static int cur_if_index;
            struct tna_interface *ifs = (struct tna_interface*) interfaces;

            cur_if_index = rtnl_link_get_ifindex(rtnl_link);

            struct tna_interface *ifs_entry = &ifs[cur_if_index -1];
        
            ifs_entry->ifindex = cur_if_index;

            ifs_entry->ifname = rtnl_link_get_name(rtnl_link);

            ifs_entry->op_state = rtnl_link_get_operstate(rtnl_link);
            char op_state_c[32];
            rtnl_link_operstate2str(ifs_entry->op_state, op_state_c, sizeof(op_state_c));
            ifs_entry->op_state_str = op_state_c;

            nl_addr = rtnl_link_get_addr(rtnl_link);
            char mac_addr_c[96];
            nl_addr2str(nl_addr, mac_addr_c, sizeof(mac_addr_c));
            ifs_entry->mac_addr_str = mac_addr_c;
 
            char *if_type = rtnl_link_get_type(rtnl_link);
            if (if_type) {
                char if_type_c[32];
                memcpy(if_type_c, if_type, sizeof(if_type_c));
                ifs_entry->type = if_type_c;
            }
            else
                ifs_entry->type = "Null";

            ifs_entry->master_index = rtnl_link_get_master(rtnl_link);
            
            get_initial_br_vlan_info(ifs_entry);

            rtnl_link_put(rtnl_link);

        }

        static void *tna_mon_nl(void *args) {
            struct nl_sock *sock = (struct nl_sock *) args;
            while(true) {
                nl_recvmsgs_default(sock);
            }
        }

        static int nlr_br_vlan_cb_func(struct nl_msg *msg, void *interface)
        {
            struct tna_interface *ifs_entry = (struct tna_interface *) interface;
            struct nlmsghdr* nlh = nlmsg_hdr(msg);
            struct ifinfomsg* if_info = (struct ifinfomsg*) (nlmsg_data(nlh));
            struct nlattr *nla = nlmsg_attrdata(nlh, 13);

            int remaining = nlmsg_attrlen(nlh, 0);

            if (ifs_entry->ifindex != if_info->ifi_index)
                return 0;

            while (nla_ok(nla, remaining)) {

                if (nla->nla_type == (IFLA_AF_SPEC)) {
                    struct nlattr *af_attr;
                    int remaining;

                    nla_for_each_nested(af_attr, nla, remaining) {
                        if (af_attr->nla_type == IFLA_BRIDGE_VLAN_INFO) {
                            struct bridge_vlan_info *vinfo;
                            vinfo = (struct bridge_vlan_info *) nla_data(af_attr);
                            if (vinfo->vid > 1) {
                                cout << "Detected VLAN on BR: " << ifs_entry->master_index << endl;
                                /* build a list of active VLANs on an interface */
                                ifs_entry->vlans[vinfo->vid].vid = vinfo->vid;
                                
                                if (vinfo->flags & BRIDGE_VLAN_INFO_UNTAGGED) {
                                    ifs_entry->vlans[vinfo->vid].is_untagged_vlan = 1;
                                    cout << "Detected untagged VLAN on BR: " << ifs_entry->master_index << endl;
                                }
                                else {
                                    ifs_entry->vlans[vinfo->vid].is_untagged_vlan = 0;
                                }
                            }
                        }
                    }

                }

                nla = nla_next(nla, &remaining);
            }
            
            return 0;
        }  

        static void get_initial_br_vlan_info(void *interface)
        {
            struct nl_sock *sk;

            struct nl_msg *msg;

            struct tna_interface *ifs_entry = (struct tna_interface *) interface;

            struct ifinfomsg ifi = {
                .ifi_family = AF_BRIDGE,
                .ifi_type = ARPHRD_NETROM,
                .ifi_index = ifs_entry->ifindex,
            };

            sk = nl_socket_alloc();
            nl_connect(sk, NETLINK_ROUTE);

            nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nlr_br_vlan_cb_func, ifs_entry);

            if (!(msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST|NLM_F_DUMP))) {
                nl_socket_free(sk);
                return;
            }


            if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
                goto nla_put_failure;
            
            //request VLAN info
            NLA_PUT_U32(msg, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN);

            nl_send_auto(sk, msg);

            nl_recvmsgs_default(sk);

            nla_put_failure:
                nlmsg_free(msg);
                nl_socket_free(sk);
                return;
        }
};


#endif