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

    int create_tna_bridge(Tnabr &tnabr, Tnanl &tnanl)
    {
        cout << "Creating TNA bridge" << endl;

        tnanl.create_tna_bridge(tnabr);

        return 0;
    }

    int update_tna_bridge(Tnabr &tnabr, Tnanl &tnanl)
    {
        cout << "Updating TNA bridge" << endl;

        return 0;
    }


    int delete_tna_bridge(Tnabr &tnabr, Tnanl &tnanl)
    {
        cout << "Deleting TNA bridge" << endl;

        return 0;
    }

}

#endif