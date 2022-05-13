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
#include <netinet/ether.h>
#include <net/if.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h> 
#include "util.h"

#define MAX_INTERFACES 32

namespace tnanl_g_ns {
	//signal nl events
    pthread_mutex_t mnl1;
    pthread_cond_t cvnl1;
    queue<struct tna_interface> tnabr_addlink_q;
    queue<struct tna_interface> tnabr_dellink_q;

    int tnanl_event_type = 0;

    int clean_g_ns(void)
    {
        pthread_mutex_lock(&tnanl_g_ns::mnl1);
        pthread_cond_signal(&cvnl1);
        pthread_mutex_unlock(&tnanl_g_ns::mnl1);

        return 0;
    }
}


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
            list<struct tna_interface>::iterator if_it;
            struct tna_bridge tnabridge;

            /*cout << "\n\nEVENT_TYPE: " << event_type << endl;
            cout << "ifname: " << interface.ifname << endl;
            cout << "ifindex: " << interface.ifindex << endl;
            cout << "master_index: " << interface.master_index << endl;
            cout << "type: " << interface.type << endl;
            cout << "opstate: " << interface.op_state_str << endl << endl;*/

            if (event_type == 1) {

                if (interface.type == "bridge") {
                    tnabridge.brname = interface.ifname;

                    if (tnabr->tnabrs[interface.ifname].brname == interface.ifname) {
                        if (interface.op_state_str == "down") {

                            for (if_it = tnabr->tnabrs[interface.ifname].brifs.begin(); if_it != tnabr->tnabrs[interface.ifname].brifs.end(); ++if_it) {
					            tnabr->uninstall_xdp_tnabr(if_it->ifindex);
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
                                if (if_it->ifindex == interface.ifindex) {
                                    ifs_exists = 1;
                                    break;
                                }
				        }
                        if (ifs_exists == 0) {
                            if (br_name) {
                                tnabridge.brname = br_name;
                                tnabr->add_if_tna_bridge(tnabridge, interface);
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
            
                        char *br_name = (char *)alloca(sizeof(char *) * IFNAMSIZ);;
                        if_indextoname(interface.master_index, br_name);
                        tnabridge.brname = br_name;
                        tnabr->remove_if_tna_bridge(tnabridge, interface);
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
            struct tna_interface ifs_entry = {0};
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

            if (attrs[IFLA_MASTER])
            {
                ifs_entry.master_index = nla_get_u32(attrs[IFLA_MASTER]);
            }

            if (attrs[IFLA_OPERSTATE])
            {
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

            //cout << "ifi_change: " << if_info->ifi_change << endl;
            //cout << "ifi_flags " << if_info->ifi_flags << endl;

            /*cout << "MSG_TYPE: " << (int) nlh->nlmsg_type << endl;
            cout << "ifname: " << ifs_entry.ifname << endl;
            cout << "ifindex: " << ifs_entry.ifindex << endl;
            cout << "master_index: " << ifs_entry.master_index << endl;
            cout << "type: " << ifs_entry.type << endl;
            cout << "opstate: " << ifs_entry.op_state_str << endl;*/
    
   
            pthread_mutex_lock(&tnanl_g_ns::mnl1);
            
            if (((int) nlh->nlmsg_type == RTM_NEWLINK) && (if_info->ifi_change > 0)) {
                event_type = 1;
                tnanl_g_ns::tnabr_addlink_q.push(ifs_entry);
            }

            if ((int) nlh->nlmsg_type == RTM_DELLINK) {
                event_type = 2;
                tnanl_g_ns::tnabr_dellink_q.push(ifs_entry);
            }
            tnanl_g_ns::tnanl_event_type = event_type;
            
            pthread_cond_signal(&tnanl_g_ns::cvnl1);
            pthread_mutex_unlock(&tnanl_g_ns::mnl1);
            
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

            //rtnl_link_put(rtnl_link);
        }

        static void *tna_mon_nl(void *args) {
            struct nl_sock *sock = (struct nl_sock *) args;
            while(true) {
                nl_recvmsgs_default(sock);
            }
        }
};


#endif