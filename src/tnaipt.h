/* TNA's service introspection - iptables */
#ifndef IPT_QUERY_H
#define IPT_QUERY_H

#include "iptables.h"

#define NUM_NF_HOOKS 5
#define NUM_IPT_TABLES 5
#define NUM_UNSUPPORTED_CHAINS 2

/* struct and flags definitions - should be moved to util.h in TNA */

//using namespace std;

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
    string ipt_chain;
    string ipt_table;
    string match_type;
    int match_flags;
    bool tna_supported;
};

struct tna_ipt_chain {
    string name;
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
            install_ipt = last_install_ipt = 0;
            pthread_create(&t1_tnipt, NULL, tna_mon_ipt, this);
        }

        void dump_ipt(void) 
        {
            _dump_ipt();
            return;
        }

        void refresh_tnaipt(void)
        {
            _refresh_tnaipt();
            return;
        }

        bool has_unsupported_rule()
        {
            if (_has_unsupported_rule())
                return true;
            else
                return false;
        }

        void update_tnaipt_state(void)
        {
            int event_type = 0;

            //if (has_unsupported_rule() || (count_ipt_rules() == 0)) {
            //    cout << "AAA" << endl;
            //    install_ipt = false;
            //    if (install_ipt != last_install_ipt) {
            //        event_type = 1;
            //        last_install_ipt = 0;
            //    }
           // }
            //else if (count_ipt_rules() > 0) {
            if (count_ipt_rules() > 6) {
                install_ipt = 1;
                //cout << "BBB" << endl;
                if (install_ipt != last_install_ipt) {
                    event_type = 2;
                    last_install_ipt = 1;
                }
            }
            
            if (event_type)
                notify_ipt_state_change(event_type);
            return;
        }

        void update_tna_ipt(int event_type)
        {
            if (event_type == 1) {
                remove_tnaipt();
            }

            else if (event_type == 2) {
                install_tnaipt();
            }
            return;
        }

        int has_ipt(void)
        {
            //cout << "install_ipt: " << install_ipt << endl;            
            return install_ipt;
        }


    private:

        const char *tablenames[NUM_IPT_TABLES] = {"nat", "filter", "mangle", "raw", "security"};
        /* We currently do not support: */
        //const char *unsupported_tables[NUM_IPT_TABLES] = {"nat", "mangle", "raw", "security"};
        string unsupported_chains[NUM_UNSUPPORTED_CHAINS] = {"INPUT", "OUTPUT"};
        
        struct tna_ipt tna_ipt;
        struct ipt_entry *e;
        pthread_t t1_tnipt;
        int install_ipt;
        int last_install_ipt; //detect change in ipt state

        //TO-DO: change logic to detect a supported iptables rule
        static void *tna_mon_ipt(void *args)
        {
            Tnaipt *tnaipt = (Tnaipt *)args;
            while (true) {
                tnaipt->refresh_tnaipt();
                tnaipt->update_tnaipt_state();
                sleep(1);
            }
            return;
        }

        void init_tna_ipt(void) 
        {
            cout << "Initializing tnaipt" << endl;
            const char *chain = NULL;
            struct xtc_handle *h;
            for(int i = 0; i < NUM_IPT_TABLES; i++) {
                struct tna_ipt_table ipt_table;
                ipt_table.name = tablenames[i];
                h = iptc_init(tablenames[i]);
                if (!h) {
                    throw runtime_error("Are you root?\n");
                }

                for(chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h)) {
                    struct tna_ipt_chain ipt_chain;
                    ipt_table.ipt_chains[chain] = ipt_chain;
                    ipt_table.ipt_chains[chain].name = chain;

                    for (e = iptc_first_rule(chain, h); e; e = iptc_next_rule(e, h)) {
                        struct tna_ipt_rule ipt_rule;
                        ipt_rule.e = e;
                        ipt_rule.tna_supported = false;
                        populate_ipt_rule(&ipt_rule);
                        ipt_table.ipt_chains[chain].ipt_rules.push_back(ipt_rule);
                    }
                }
                iptc_free(h);
                tna_ipt.ipt_tables.push_back(ipt_table);
            }
        }

        void _refresh_tnaipt(void)
        {
            //cout << "Here" << endl;
            unordered_map<string, struct tna_ipt_chain>::iterator ipt_chain_it;
            struct xtc_handle *h;

            for (int i = 0; i < tna_ipt.ipt_tables.size(); i++) {
            
                for (ipt_chain_it = tna_ipt.ipt_tables[i].ipt_chains.begin(); ipt_chain_it != tna_ipt.ipt_tables[i].ipt_chains.end(); ++ipt_chain_it) {
                    h = iptc_init(tna_ipt.ipt_tables[i].name.c_str());
                    ipt_chain_it->second.ipt_rules.clear();
                    if (!(h)) {
                        cout << "Cannot update tnaipt\n";
                        break;
                    }
                    for (e = iptc_first_rule(ipt_chain_it->first.c_str(), h); e; e = iptc_next_rule(e, h)) {
                        struct tna_ipt_rule ipt_rule;
                        ipt_rule.e = e;
                        ipt_rule.ipt_chain = ipt_chain_it->first.c_str();
                        ipt_rule.ipt_table = tna_ipt.ipt_tables[i].name.c_str();
                        ipt_rule.tna_supported = false;
                        populate_ipt_rule(&ipt_rule);
                        tna_ipt.ipt_tables[i].ipt_chains[ipt_chain_it->first.c_str()].ipt_rules.push_back(ipt_rule);
                    }
                    iptc_free(h);
                }
            }

            return;
        }

        void remove_tnaipt(void) 
        {
            cout << "Removing Tnaipt ..." << endl;
        }

        void install_tnaipt(void)
        {
            cout << "Installing Tnaipt ..." << endl;
        }

        void notify_ipt_state_change(int event_type)
        {
            struct tna_event tna_event;
            pthread_mutex_lock(&tna_g_ns::m1);

            tna_event.event_type = event_type;
            tna_event.event_flag = tna_g_ns::TNA_IPT_EVENT;

            tna_g_ns::tna_event_q.push(tna_event);
            
            pthread_cond_signal(&tna_g_ns::cv1);
            pthread_mutex_unlock(&tna_g_ns::m1);
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
                    cout << "Number of ipt rules: " << count_ipt_rules_chain(ipt_chain_it->second) << endl;                                             
                }
            }
        }

        //int count_ipt_rules(struct tna_ipt tna_ipt)
        int count_ipt_rules(void)
        {
            unordered_map<string, struct tna_ipt_chain>::iterator ipt_chain_it;
            int total = 0;
            for (int i = 0; i < tna_ipt.ipt_tables.size(); i++) {
                for (ipt_chain_it = tna_ipt.ipt_tables[i].ipt_chains.begin(); ipt_chain_it != tna_ipt.ipt_tables[i].ipt_chains.end(); ++ipt_chain_it) {
                    total += count_ipt_rules_chain(ipt_chain_it->second);                       
                }
            }
            //cout << "total" << total << endl;
            return total;
        }

        int count_ipt_rules_chain(struct tna_ipt_chain ipt_chain)
        {
            return ipt_chain.ipt_rules.size();
        }

        void populate_ipt_rule(struct tna_ipt_rule *ipt_rule)
        {
            if (check_tna_rule_support(ipt_rule))
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

        //bool check_tna_rule_support(struct ipt_entry *e)
        bool check_tna_rule_support(struct tna_ipt_rule *tna_ipt_rule)
        {
            //checks if rule is currently supported by TNA
            //can use iptc_builtin to verify the presence of a non-builtin rule.
            bool supported = true;

            if (get_match_flags(tna_ipt_rule->e) & M_UNSUPPORTED_MATCH_FLAGS)
                supported = false;

            for (int i = 0; i < NUM_UNSUPPORTED_CHAINS; i++) {
                if (strcmp(tna_ipt_rule->ipt_chain.c_str(), unsupported_chains[i].c_str()) == 0) {
                    supported = false;
                }
            }
            
            return supported;
        }

        bool _has_unsupported_rule(void)
        {
            bool unsupported = false;
            unordered_map<string, struct tna_ipt_chain>::iterator ipt_chain_it;

            for (int i = 0; i < tna_ipt.ipt_tables.size(); i++) {

                for (ipt_chain_it = tna_ipt.ipt_tables[i].ipt_chains.begin(); ipt_chain_it != tna_ipt.ipt_tables[i].ipt_chains.end(); ++ipt_chain_it) {

                    for (int j = 0; j < ipt_chain_it->second.ipt_rules.size(); j++) {

                        if (!ipt_chain_it->second.ipt_rules[j].tna_supported) {
                            unsupported = true;
                            break;
                        }
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