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
        int event_type;

        pthread_mutex_lock(&tna_g_ns::m1);
        while (tna_g_ns::tna_event_type == 0) 
            pthread_cond_wait(&tna_g_ns::cv1, &tna_g_ns::m1);
        
        event_type = tna_g_ns::tna_event_type;
        ifs_entry = tna_g_ns::interface_g;
        
        

        if (!(tnatm->tnaodb.tnaifs.find(ifs_entry.ifname) == tnatm->tnaodb.tnaifs.end())) {
            /* Interface already exists */
            ifs_entry_tmp = tnatm->tnaodb.tnaifs[ifs_entry.ifname];
            tnatm->tnaodb.tnaifs[ifs_entry.ifname] = ifs_entry;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].ref_cnt = ifs_entry_tmp.ref_cnt;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].xdp_set = ifs_entry_tmp.xdp_set;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].tna_svcs = ifs_entry_tmp.tna_svcs;
        }
        else {
            tnatm->tnaodb.tnaifs[ifs_entry.ifname] = ifs_entry;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].ref_cnt = 0;
            tnatm->tnaodb.tnaifs[ifs_entry.ifname].xdp_set = 0;
        }

        if (tna_g_ns::tna_event_flag & tna_g_ns::TNA_BR_EVENT) {
            tnatm->tnaodb.tnabr->update_tna_bridge(&tnatm->tnaodb.tnaifs[ifs_entry.ifname]);
        }

        tnatm->update_tna_topo();
        tnatm->tna_topo_print();
        
        if (tnatm->tna_topo_changed()) {
            cout << "Detected topology change\n";
            tnatm->deploy_tnafp();
        }


        tna_g_ns::tna_event_type = 0;
        tna_g_ns::tna_event_flag = 0;

        pthread_mutex_unlock(&tna_g_ns::m1);

        return 0;
    }

}

#endif
