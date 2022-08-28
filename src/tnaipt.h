#ifndef IPT_QUERY_H
#define IPT_QUERY_H

#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <cstdlib>
#include <unistd.h>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <memory>
#include <libiptc/libiptc.h>
#include "iptables.h"

#define NUM_NF_HOOKS 5
#define NUM_IPT_TABLES 5

/* struct and flags definitions - should be moved to util.h in TNA */

using namespace std;

/* TNA match flags definition */
enum ipt_match_flags {
    M_SIP = 1 << 0,
    M_DIP = 1 << 1,
    M_PROTO = 1 << 2,
    M_TCP = 1 << 3,
    M_UDP = 1 << 4,
    M_CONNTRACK = 1 << 5,
    M_UNSUPPORTED_MATCH_FLAGS = (M_TCP | M_UDP | M_CONNTRACK)
};

struct tna_ipt_rule {
    struct ipt_entry *e;
    string target;
    string match_type;
    int match_flags;
    bool tna_supported;
};

struct tna_ipt_chain {
    string name;
    //unordered_map<string, struct ipt_entry*> ipt_entries;
    //vector  <struct ipt_entry> ipt_entries;
    vector <struct tna_ipt_rule> ipt_rules;
};

struct tna_ipt_table {
    string name;
    unordered_map<string, struct tna_ipt_chain> ipt_chains;
    struct xtc_handle *h;
};

struct tna_ipt {
    vector<struct tna_ipt_table> ipt_tables;
};

class Tnaipt {
    public:
        Tnaipt(void) 
        {
            init_tna_ipt();
        }

        void dump_ipt(void) 
        {
            _dump_ipt();
        }

        void refresh_tnaipt(void)
        {
            _refresh_tnaipt();
        }

        bool has_unsupported_rule()
        {
            if (_has_unsupported_rule())
                return true;
                //cout << "unsupported\n";
            else
                return false;
        }

    private:

        //struct ipt_ip ipt_ip;
        const char *tablenames[NUM_IPT_TABLES] = {"nat", "filter", "mangle", "raw", "security"};
        /* We currently do not support: */
        const char *unsupported_tables[NUM_IPT_TABLES] = {"nat", "mangle", "raw", "security"};
        //const char *unsupported_chains[NUM_NF_HOOKS] = {"...", }
        
        struct tna_ipt tna_ipt;
        struct ipt_entry *e;

        void init_tna_ipt(void) 
        {
            cout << "Initializing tnaipt" << endl;
            const char *chain = NULL;
            for(int i = 0; i < NUM_IPT_TABLES; i++) {
                struct tna_ipt_table ipt_table;
                ipt_table.name = tablenames[i];
                ipt_table.h = iptc_init(tablenames[i]);
                if (!ipt_table.h) {
                    throw runtime_error("Are you root?\n");
                }

                for(chain = iptc_first_chain(ipt_table.h); chain; chain = iptc_next_chain(ipt_table.h)) {
                    struct tna_ipt_chain ipt_chain;
                    ipt_table.ipt_chains[chain] = ipt_chain;
                    ipt_table.ipt_chains[chain].name = chain;

                    for (e = iptc_first_rule(chain, ipt_table.h); e; e = iptc_next_rule(e, ipt_table.h)) {
                        //struct ipt_entry e;
                        struct tna_ipt_rule ipt_rule;
                        ipt_rule.e = e;
                        ipt_rule.tna_supported = false;
                        populate_ipt_rule(&ipt_rule);
                        ipt_table.ipt_chains[chain].ipt_rules.push_back(ipt_rule);
                    }
                }
                tna_ipt.ipt_tables.push_back(ipt_table);
            }
        }

        void _refresh_tnaipt(void)
        {
            unordered_map<string, struct tna_ipt_chain>::iterator ipt_chain_it;

            for (int i = 0; i < tna_ipt.ipt_tables.size(); i++) {
            
                for (ipt_chain_it = tna_ipt.ipt_tables[i].ipt_chains.begin(); ipt_chain_it != tna_ipt.ipt_tables[i].ipt_chains.end(); ++ipt_chain_it) {
                    tna_ipt.ipt_tables[i].h = iptc_init(tna_ipt.ipt_tables[i].name.c_str());
                    ipt_chain_it->second.ipt_rules.clear();
                    
                    for (e = iptc_first_rule(ipt_chain_it->first.c_str(), tna_ipt.ipt_tables[i].h); e; e = iptc_next_rule(e, tna_ipt.ipt_tables[i].h)) {
                        struct tna_ipt_rule ipt_rule;
                        ipt_rule.e = e;
                        ipt_rule.tna_supported = false;
                        populate_ipt_rule(&ipt_rule);
                        tna_ipt.ipt_tables[i].ipt_chains[ipt_chain_it->first.c_str()].ipt_rules.push_back(ipt_rule);
                    }
                }
            }

            return;
        }
        

        void _dump_ipt(void)
        {
            unordered_map<string, struct tna_ipt_chain>::iterator ipt_chain_it;
            cout << tna_ipt.ipt_tables.size() << endl;
            for (int i = 0; i < tna_ipt.ipt_tables.size(); i++) {
                cout << "Table name: " << tna_ipt.ipt_tables[i].name << endl;
                cout << "Chains: " << endl;
                for (ipt_chain_it = tna_ipt.ipt_tables[i].ipt_chains.begin(); ipt_chain_it != tna_ipt.ipt_tables[i].ipt_chains.end(); ++ipt_chain_it) {
                    cout << ipt_chain_it->second.name << endl;
                    cout << "Number of ipt rules: " << count_ipt_rules(ipt_chain_it->second) << endl;                       
                }
            }
        }

        int count_ipt_rules(struct tna_ipt_chain ipt_chain) 
        {
            return ipt_chain.ipt_rules.size();
        }

        bool has_ipt_rules(struct tna_ipt_chain ipt_chain)
        {
            if (count_ipt_rules(ipt_chain) > 0)
                return true;
            else
                return false;
        }

        void populate_ipt_rule(struct tna_ipt_rule *ipt_rule)
        {
            if (check_tna_rule_support(ipt_rule->e))
                ipt_rule->tna_supported = true;
            
            return;
        }

        /* Gets IP header match flags - How to get tcp header matching info?*/ 
        int get_match_flags(struct ipt_entry *e) 
        {
            int match_flags = 0;

            if (e->ip.src.s_addr)
                match_flags |= M_SIP;
            if (e->ip.dst.s_addr)
                match_flags |= M_DIP;
            if (e->ip.proto)
                match_flags |= M_PROTO;

            IPT_MATCH_ITERATE(e, check_match, &e->ip, &match_flags);

            return match_flags;
        }

        static int check_match(const struct xt_entry_match *m, const struct ipt_ip *ip, int *match_flags)
        {
            const char *name = m->u.user.name;
            
            if (!strcmp(name, "tcp"))
                *match_flags |= M_TCP;

            if (!strcmp(name, "udp"))
                *match_flags |= M_UDP;            

            if (!strcmp(name, "conntrack"))
                *match_flags |= M_CONNTRACK;

            return 0;
        }

        bool check_tna_rule_support(struct ipt_entry *e)
        {
            //checks if rule is currently supported by TNA
            //can use iptc_builtin to verify the presence of a non-builtin rule.
            bool supported = true;

            if (get_match_flags(e) & M_UNSUPPORTED_MATCH_FLAGS)
                supported = false;
            
            return supported;
        }

        //TO-DO: add logic to detect unsupported rule on given a chain
        //TO-DO: add logic to detect the reason why a rule is unsupported (e.g., unsupported match, table or chain)  
        bool _has_unsupported_rule(void)
        {
            bool unsupported = false;
            unordered_map<string, struct tna_ipt_chain>::iterator ipt_chain_it;

            for (int i = 0; i < tna_ipt.ipt_tables.size(); i++) {

                for (ipt_chain_it = tna_ipt.ipt_tables[i].ipt_chains.begin(); ipt_chain_it != tna_ipt.ipt_tables[i].ipt_chains.end(); ++ipt_chain_it) {

                    for(int j = 0; j < ipt_chain_it->second.ipt_rules.size(); j++) {

                        if (!ipt_chain_it->second.ipt_rules[j].tna_supported)
                            unsupported = true;
                    }
                }
            }
            return unsupported;
        }

        //TO-DO
        bool check_tna_table_support(const char *table)
        {
            bool unsupported = false;

            return unsupported;
        }

        
        bool check_tna_chain_support(const char *chain)
        {
            bool unsupported = false;

            return unsupported;
        }
};

#endif