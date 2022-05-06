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
#include "util.h"

#define MAX_INTERFACES 32

class Tnanl {
    public:
        Tnanl(void) 
        {
           connect_nlr();
           build_link_nl_cache();
        }

       ~Tnanl(void) 
       {
           close_nlr();
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

        void create_tna_bridge(Tnabr &tnabr)
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
                    tnabr.add_tna_bridge(tnabridge);

                    for (int i = 0; i < MAX_INTERFACES; i++) {
                         if (interfaces[i].master_index == master_index) {
                            tnabr.add_if_tna_bridge(tnabridge, interfaces[i]);
                         }
                    }
                    tnabr.accel_tna_bridge(tnabridge); //move this to tna.h   
                }
            }

        }

    private:
        int _fml;
        struct nl_sock *sk;
        struct nl_cache *link_nl_cache;
       
        int connect_nlr() 
        {
            cout << "Connecting to NETLINK_ROUTE socket ..." << endl; 

            _fml = NETLINK_ROUTE;
            sk = nl_socket_alloc();
            nl_connect(sk, _fml);

            return 0;
        }

        int close_nlr()
        {
            cout << "Closing NETLINK_ROUTE socket" << endl;

            //drop memberships as well
            nl_socket_free(sk);
            return 0;
        }

        int build_link_nl_cache(void)
        {
            cout << "\nBuilding rtnl_cache ..." << endl;

            if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_nl_cache) < 0)
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
};


#endif