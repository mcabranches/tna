/* TNA's service instrospection - Netlink */
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
#include <netlink/route/link/bridge.h>
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
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "tnabr.h"
#include "tnatm.h"

class Tnanl {

    public:
        Tnanl(void) 
        {
            cout << "Initializing Service Instrospection" << endl;
            connect_nlr_q();
            build_nl_cache();
            add_membership_nlr(this);
            pthread_create(&t1_tnanl, NULL, tna_mon_nl, nlr_g_sk);
        }

        ~Tnanl(void) 
        {
            close_nlr_q();
            drop_membership_nlr();
            nl_cache_put(link_nl_cache);
            nl_cache_put(addr_nl_cache);
            pthread_cond_destroy(&tna_g_ns::cv1);
            pthread_mutex_destroy(&tna_g_ns::m1);
        }

        void dump_cached_interfaces(void)
        {
            struct tna_interface interfaces[MAX_INTERFACES] = { 0 };
            nl_cache_foreach(link_nl_cache, link_cache_cb, &interfaces);
            nl_cache_foreach(addr_nl_cache, addr_cache_cb, &interfaces);
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

        void init_tna_objects(Tnatm *tnatm)
        {
            struct tna_interface interfaces[MAX_INTERFACES] = { 0 };
            nl_cache_foreach(link_nl_cache, link_cache_cb, &interfaces);
            nl_cache_foreach(addr_nl_cache, addr_cache_cb, &interfaces);
            this->tnatm = tnatm;
            this->tnatm->create_tna_object(interfaces);
        }

        int build_nl_cache(void)
        {
            //cout << "\nBuilding rtnl_cache ..." << endl;

            if (rtnl_link_alloc_cache(nlr_q_l_sk, AF_UNSPEC, &link_nl_cache) < 0)
                cout << "Error building link rtnl_cache ..." << endl;
            if (rtnl_addr_alloc_cache(nlr_q_a_sk, &addr_nl_cache) < 0) //01/31/2023 -> put this on another socket
                cout << "Error building addr addr_cache ..." << endl;


            return 0;
        }

    private:
        struct nl_sock *nlr_q_l_sk; //cache query nl route socket (link)
        struct nl_sock *nlr_q_a_sk; //cache query nl route socket (address)
        struct nl_sock *nlr_g_sk; //multicast group nl route socket
        struct nl_cache *link_nl_cache;
        struct nl_cache *addr_nl_cache;
        Tnatm *tnatm;
        pthread_t t1_tnanl;
       
        int connect_nlr_q(void) 
        {
            //cout << "Connecting to NETLINK_ROUTE socket ..." << endl; 

            nlr_q_l_sk = nl_socket_alloc();
            nlr_q_a_sk = nl_socket_alloc();
            nl_connect(nlr_q_l_sk, NETLINK_ROUTE);
            nl_connect(nlr_q_a_sk, NETLINK_ROUTE);

            return 0;
        }

        int close_nlr_q(void)
        {
            //cout << "Closing NETLINK_ROUTE socket" << endl;

            nl_socket_free(nlr_q_l_sk);
            nl_socket_free(nlr_q_a_sk);

            return 0;
        }

        static int nlr_g_cb(struct nl_msg *msg, void *arg)
        {
            //cout << "Received NETLINK_ROUTE event" << endl;
            pthread_mutex_lock(&tna_g_ns::m1);
            int stop = tna_g_ns::tna_stop;
            pthread_mutex_unlock(&tna_g_ns::m1);
            if (stop)
                return 0;
    
            struct nlmsghdr* nlh = nlmsg_hdr(msg);
            Tnanl *self = arg;
            struct ifinfomsg* if_info = (struct ifinfomsg*) (nlmsg_data(nlh));
            struct bridge_vlan_info *vinfo;
            struct tna_interface ifs_entry = { 0 };
            struct tna_event tna_event;
            int nlmsg_type = (int) nlh->nlmsg_type;

            ifs_entry.ifindex = if_info->ifi_index;
            ifs_entry.type = "Null";

            self->build_nl_cache();
            self->get_cached_interface(&ifs_entry);

            //cout << "ifs_entry.ifname: " << ifs_entry.ifname << endl;

            if (nlmsg_type == RTM_NEWLINK || nlmsg_type == RTM_DELLINK) 
                self->parse_ifla(nlh, if_info, &ifs_entry, &tna_event, self);

            if (nlmsg_type == RTM_NEWADDR || nlmsg_type == RTM_DELADDR)
                self->parse_ifa(nlh, if_info, &ifs_entry, &tna_event, self);

            if (nlmsg_type == RTM_NEWROUTE || nlmsg_type == RTM_DELROUTE)
                self->parse_rtn(nlh, if_info, &ifs_entry, &tna_event, self);


            tna_event.interface = ifs_entry;
            tna_event.event_type = ifs_entry.tna_event_type;


            pthread_mutex_lock(&tna_g_ns::m1);

            tna_g_ns::tna_event_q.push(tna_event);
            
            pthread_cond_signal(&tna_g_ns::cv1);
            pthread_mutex_unlock(&tna_g_ns::m1);
            
            return 0;
        }


        void parse_ifla(struct nlmsghdr* nlh, struct ifinfomsg* if_info, 
                            struct tna_interface* ifs_entry, struct tna_event* tna_event, Tnanl *self) 
        {
            
            struct bridge_vlan_info *vinfo;
            struct nlattr *attrs[IFLA_MAX+1];
            
            if (nlmsg_parse(nlh, sizeof(struct nlmsghdr), attrs, IFLA_MAX, rtln_link_policy) < 0) {
                /* error */
                cout << "Error parsing NL attributes\n";            
            }

            if (attrs[IFLA_IFNAME]) {
                ifs_entry->ifname = nla_get_string(attrs[IFLA_IFNAME]);
            }

            if (attrs[IFLA_MASTER]) {
                ifs_entry->master_index = nla_get_u32(attrs[IFLA_MASTER]);
            }

            if (attrs[IFLA_OPERSTATE]) {
                char op_state_c[32];
                ifs_entry->op_state = nla_get_u32(attrs[IFLA_OPERSTATE]);
                rtnl_link_operstate2str(ifs_entry->op_state, op_state_c, sizeof(op_state_c));
                ifs_entry->op_state_str = op_state_c;
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
                        ifs_entry->type = kind;
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
                            ifs_entry->vlans[vinfo->vid].vid = vinfo->vid;
                            if (vinfo->flags & BRIDGE_VLAN_INFO_UNTAGGED) {
                                ifs_entry->vlans[vinfo->vid].is_untagged_vlan = 1;
                            }
                            else {
                                ifs_entry->vlans[vinfo->vid].is_untagged_vlan = 0;
                            }
                        }
                    }
                }
            }

            if (ifs_entry->type == "Null")
                ifs_entry->type = "phys";

            if (ifs_entry->ifindex == ifs_entry->master_index) {
                ifs_entry->type = "bridge";
                tna_event->event_flag |= tna_g_ns::TNA_BR_EVENT;
            }

            if (if_info->ifi_flags && if_info->ifi_change) {
                if (if_info->ifi_flags & IFF_UP)
                    ifs_entry->op_state_str = "up";
                else
                    ifs_entry->op_state_str = "down";
            }

            if ((int) nlh->nlmsg_type == RTM_NEWLINK)
                ifs_entry->tna_event_type = 1;
            
            if ((int) nlh->nlmsg_type == RTM_DELLINK)
                ifs_entry->tna_event_type = 2;


            else if (!(if_info->ifi_change))
                ifs_entry->tna_event_type = 0;

            
            tna_event->event_flag |= tna_g_ns::TNA_BR_EVENT;
        }

        void parse_ifa(struct nlmsghdr* nlh, struct ifinfomsg* if_info, 
                            struct tna_interface* ifs_entry, struct tna_event* tna_event, Tnanl *self) 
        {
            struct ifaddrmsg *iface = (struct ifaddrmsg *)nlmsg_data(nlh);
            struct nlattr *attrs[IFA_MAX+1];
            
            if (nlmsg_parse(nlh, sizeof(struct ifaddrmsg), attrs, IFA_MAX, NULL) < 0) {
                cout << "Error parsing NL attributes\n";            
            }
            if (attrs[IFA_ADDRESS])
                inet_ntop(iface->ifa_family, nla_data(attrs[IFA_ADDRESS]), ifs_entry->ip4Addr, sizeof(ifs_entry->ip4Addr));

            if (attrs[IFA_LABEL])
                ifs_entry->ifname = nla_get_string(attrs[IFA_LABEL]);

            if (ifs_entry->ifname.length() == 0)
                return -1;
            
            if ((int) nlh->nlmsg_type == RTM_NEWADDR) {
                if (ifs_entry->ip4Addr) {
                    ifs_entry->has_l3 = 1;
                    self->tnatm->tnaodb.tnaifs[ifs_entry->ifname].has_l3 = 1;
                    tna_event->event_flag |= tna_g_ns::TNA_RTR_EVENT;
                }
            }
            else if ((int) nlh->nlmsg_type == RTM_DELADDR) {
                ifs_entry->has_l3 = 0;
                self->tnatm->tnaodb.tnaifs[ifs_entry->ifname].has_l3 = 0;
                tna_event->event_flag |= tna_g_ns::TNA_RTR_EVENT;
            }

            if ((self->tnatm->tnaodb.tnaifs[ifs_entry->ifname].master_index != 0)
                                            || (ifs_entry->type ==  "bridge"))
                tna_event->event_flag |= tna_g_ns::TNA_BR_EVENT;
        }

        void parse_rtn(struct nlmsghdr* nlh, struct ifinfomsg* if_info, 
                            struct tna_interface* ifs_entry, struct tna_event* tna_event, Tnanl *self) 
        {
            static char ip4Addr[INET_ADDRSTRLEN];
            struct ifaddrmsg *iface = (struct ifaddrmsg *)nlmsg_data(nlh);

            struct nlattr *attrs[IFA_MAX+1];
            
            if (nlmsg_parse(nlh, sizeof(struct ifaddrmsg), attrs, IFA_MAX, NULL) < 0) {
                /* error */
                cout << "Error parsing NL attributes\n";            
            }
            if (attrs[IFA_ADDRESS])
                inet_ntop(iface->ifa_family, nla_data(attrs[IFA_ADDRESS]), ip4Addr, sizeof(ip4Addr));
            
            if (ip4Addr)
                ifs_entry->has_l3 = 1;
            else
                ifs_entry->has_l3 = 0;
        }

        void dump_nl_attrs(struct nlmsghdr* nlh, struct ifinfomsg* if_info, 
                                    struct tna_interface ifs_entry)
        {
            cout << "family: " << if_info->ifi_family << endl;
            cout << "type: " << if_info->ifi_type << endl;
            cout << "ifi_change: " << if_info->ifi_change << endl;
            cout << "ifi_flags " << if_info->ifi_flags << endl;
            cout << "MSG_TYPE: " << (int) nlh->nlmsg_type << endl;
            cout << "ifname: " << ifs_entry.ifname << endl;
        }

        int add_membership_nlr(Tnanl *self)
        {
            //cout << "Adding NETLINK_ROUTE multicast membership" << endl;

            nlr_g_sk = nl_socket_alloc();
            nl_socket_disable_seq_check(nlr_g_sk);
            nl_socket_modify_cb(nlr_g_sk, NL_CB_VALID, NL_CB_CUSTOM, nlr_g_cb, self);
            nl_connect(nlr_g_sk, NETLINK_ROUTE);
            nl_socket_add_memberships(nlr_g_sk, RTNLGRP_LINK, 0);
            nl_socket_add_memberships(nlr_g_sk, RTNLGRP_IPV4_IFADDR, 0);
            nl_socket_add_memberships(nlr_g_sk, RTNLGRP_IPV4_ROUTE, 0);

            return 0;
        }

        int drop_membership_nlr(void)
        {
            //cout << "Dropping NETLINK_ROUTE multicast membership" << endl;

            nl_socket_drop_memberships(nlr_g_sk, RTNLGRP_LINK, 0);
            nl_socket_drop_memberships(nlr_g_sk, RTNLGRP_IPV4_IFADDR, 0);
            nl_socket_drop_memberships(nlr_g_sk, RTNLGRP_IPV4_ROUTE, 0);
            nl_socket_free(nlr_g_sk);

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

        }

        static void addr_cache_cb(struct nl_object *nl_object, void *interfaces)
        {
            struct rtnl_addr *rtnl_addr = (struct rtnl_addr *)nl_object;
            struct tna_interface *ifs = (struct tna_interface*) interfaces;

            if (!rtnl_addr) {
                cout << "Could not get addr" << endl;
                return;
            }

            //Only dump IPV4
            if (rtnl_addr_get_family(rtnl_addr) != NFPROTO_IPV4)
                return;

            int cur_if_index = rtnl_addr_get_ifindex(rtnl_addr);
            struct tna_interface *ifs_entry = &ifs[cur_if_index - 1];
        
            ifs_entry->ifindex = cur_if_index;

            const struct nl_addr *nl_addr_local = rtnl_addr_get_local(rtnl_addr);

            if (!nl_addr_local) {
                cout << "rtnl_addr_get_local() failed" << endl;
                return;
            }

            nl_addr2str(nl_addr_local, ifs_entry->ip4Addr, sizeof(ifs_entry->ip4Addr));

            if (!ifs_entry->ip4Addr) {
                cout << "nl_addr2str() failed" << endl;
                return;
            }
            else 
                ifs_entry->has_l3 = 1;

        }

        //Service introspection thread main loop
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
            
            ifs_entry->has_vlan = 0;

            while (nla_ok(nla, remaining)) {

                if (nla->nla_type == (IFLA_AF_SPEC)) {
                    struct nlattr *af_attr;
                    int remaining;

                    nla_for_each_nested(af_attr, nla, remaining) {
                        if (af_attr->nla_type == IFLA_BRIDGE_VLAN_INFO) {
                            struct bridge_vlan_info *vinfo;
                            vinfo = (struct bridge_vlan_info *) nla_data(af_attr);
                            if (vinfo->vid > 1) {
                                /* build a list of active VLANs on an interface */
                                ifs_entry->vlans[vinfo->vid].vid = vinfo->vid;
                                ifs_entry->has_vlan = 1;
                                
                                if (vinfo->flags & BRIDGE_VLAN_INFO_UNTAGGED) {
                                    ifs_entry->vlans[vinfo->vid].is_untagged_vlan = 1;                                }
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

        void get_cached_interface(struct tna_interface* ifs_entry)
        {
            struct tna_interface interfaces[MAX_INTERFACES] = { 0 };
            nl_cache_foreach(link_nl_cache, link_cache_cb, &interfaces);
            nl_cache_foreach(addr_nl_cache, addr_cache_cb, &interfaces);
            for (int i = 0; i < MAX_INTERFACES; i++) {
                if (interfaces[i].ifindex == ifs_entry->ifindex) {
                    *ifs_entry = interfaces[i];
                    break;
                }
            }
            return;
        }
};

#endif