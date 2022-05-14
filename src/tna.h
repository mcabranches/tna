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

        tna_interface ifs_entry = {0};

        pthread_mutex_lock(&tnanl_g_ns::mnl1);
        while (tnanl_g_ns::tnanl_event_type == 0) 
            pthread_cond_wait(&tnanl_g_ns::cvnl1, &tnanl_g_ns::mnl1);

        tnanl->update_tna_bridge(tnabr, tnanl_g_ns::interface_g, tnanl_g_ns::tnanl_event_type);

        tnanl_g_ns::tnanl_event_type = 0;   

        pthread_mutex_unlock(&tnanl_g_ns::mnl1);

        return 0;
    }

}

#endif