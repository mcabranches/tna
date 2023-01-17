#ifndef TNA_H
#define TNA_H

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <linux/if_link.h>
#include "tnanl.h"
#include "tnatm.h"
#include "tnabr.h"
#include "tnaipt.h"
#include "tnafpd.h"

namespace tna {

    int process_tna_event(Tnanl *tnanl, Tnatm *tnatm)
    {

        tna_interface ifs_entry, ifs_entry_tmp;
        struct tna_event event;
        int event_type;
        int event_flag;

        pthread_mutex_lock(&tna_g_ns::m1);
        while (tna_g_ns::tna_event_q.empty())
            pthread_cond_wait(&tna_g_ns::cv1, &tna_g_ns::m1);

        event = tna_g_ns::tna_event_q.front(); //get event
        tna_g_ns::tna_event_q.pop(); //remove event

        event_type = event.event_type;
        event_flag = event.event_flag;
        ifs_entry = event.interface;
        
        if (event_type == tna_g_ns::TNA_STOP)
            return 0;
        

        if (!(tnatm->tnaodb.tnaifs.find(ifs_entry.ifname) == tnatm->tnaodb.tnaifs.end())) {
            /* Interface already exists */
            ifs_entry_tmp = tnatm->tnaodb.tnaifs[ifs_entry.ifname];
            tnatm->tnaodb.tnaifs[ifs_entry.ifname] = ifs_entry;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].ref_cnt = ifs_entry_tmp.ref_cnt;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].xdp_set = ifs_entry_tmp.xdp_set;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].tna_svcs = ifs_entry_tmp.tna_svcs;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].type = ifs_entry_tmp.type;
            //tnatm->tnaodb.tnaifs[ifs_entry.ifname].op_state = ifs_entry_tmp.op_state;
        }
        else {
            tnatm->tnaodb.tnaifs[ifs_entry.ifname] = ifs_entry;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].ref_cnt = 0;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].xdp_set = 0;
        }

        if (event_flag & tna_g_ns::TNA_BR_EVENT) {
            cout << "TNA_BR_EVENT" << endl;
            tnatm->tnaodb.tnabr->update_tna_bridge(&tnatm->tnaodb.tnaifs[ifs_entry.ifname]);
        }

        if (event_flag & tna_g_ns::TNA_RTR_EVENT) {
            cout << "TNA_RTR_EVENT" << endl;
            tnatm->tnaodb.tnartr->update_tna_rtr(&tnatm->tnaodb.tnaifs[ifs_entry.ifname]);
        }

        tnatm->update_tna_topo();
        tnatm->tna_topo_print();
        
        if (tnatm->tna_topo_changed()) {
            cout << "Detected topology change\n";
            tnatm->deploy_tnafp();
        }

        pthread_mutex_unlock(&tna_g_ns::m1);

        return 0;
    }

}

#endif
