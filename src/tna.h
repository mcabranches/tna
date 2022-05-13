#ifndef TNA_H
#define TNA_H

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <linux/if_link.h>
#include "tnabr.h"
#include "tnanl.h"

namespace tna {

    int create_tna_bridge(Tnabr *tnabr, Tnanl *tnanl)
    {
        cout << "Creating TNA bridge" << endl;

        tnanl->create_tna_bridge(tnabr);

        return 0;
    }

    int delete_tna_bridge(Tnabr *tnabr, Tnanl *tnanl)
    {
        cout << "Deleting TNA bridge" << endl;

        return 0;
    }

    int process_tnanl_event(Tnabr *tnabr, Tnanl *tnanl)
    {
        pthread_mutex_lock(&tnanl_g_ns::mnl1);
        pthread_cond_wait(&tnanl_g_ns::cvnl1, &tnanl_g_ns::mnl1);
        tna_interface ifs_entry = {0};
        
        if (tnanl_g_ns::tnanl_event_type == 1) {
            while (!tnanl_g_ns::tnabr_addlink_q.empty()) {
                ifs_entry = tnanl_g_ns::tnabr_addlink_q.front();
                tnanl->update_tna_bridge(tnabr, ifs_entry, tnanl_g_ns::tnanl_event_type);
                tnanl_g_ns::tnabr_addlink_q.pop();
            }
        }

        if (tnanl_g_ns::tnanl_event_type == 2) {
            while (!tnanl_g_ns::tnabr_dellink_q.empty()) {
                ifs_entry = tnanl_g_ns::tnabr_dellink_q.front();
                tnanl->update_tna_bridge(tnabr, ifs_entry, tnanl_g_ns::tnanl_event_type);
                tnanl_g_ns::tnabr_dellink_q.pop();
            }
        }

        
        pthread_mutex_unlock(&tnanl_g_ns::mnl1);

        return 0;
    }

}

#endif