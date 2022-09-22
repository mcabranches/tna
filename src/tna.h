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
#include "tnaipt.h"

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

    int process_tna_event(Tnabr *tnabr, Tnanl *tnanl, Tnaipt *tnaipt)
    {

        tna_interface ifs_entry;
        int event_type;

        pthread_mutex_lock(&tna_g_ns::m1);
        while (tna_g_ns::tna_event_type == 0) 
            pthread_cond_wait(&tna_g_ns::cv1, &tna_g_ns::m1);
        
        event_type = tna_g_ns::tna_event_type;

        //tnanl->update_state_tna_bridge(tnabr, tna_g_ns::interface_g);
        if (tna_g_ns::tna_event_flag & tna_g_ns::TNA_BR_EVENT) {
            ifs_entry = tna_g_ns::interface_g;
            tnanl->update_tna_bridge(tnabr, ifs_entry, event_type);
        }

        else if ((tna_g_ns::tna_event_flag & tna_g_ns::TNA_IPT_EVENT)) {
            //tnaipt->update_tnaipt(event_type);
        }

        tna_g_ns::tna_event_type = 0;
        tna_g_ns::tna_event_flag = 0;

        pthread_mutex_unlock(&tna_g_ns::m1);

        return 0;
    }

}

#endif