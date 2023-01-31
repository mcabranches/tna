#ifndef TNARTR_H
#define TNARTR_H

#include "util.h"

class Tnartr {
    public:
        Tnartr(void)
        {
            cout << "Creating tnartr object" << endl;
        }

        ~Tnartr(void)
        {
            destroy_tnartr();
        }

        int destroy_tnartr(void)
        {
            _destroy_tnartr();
            return 0;
        }

        int update_tna_rtr(struct tna_interface *interface)
        {
            cout << "Updating tnartr" << endl;
            return 0;
        }
    
    private:
        //implement clean up routine (if needed)
        int _destroy_tnartr(void) 
        {
            cout << "Delete Tnartr" << endl;

            return 0;
        }
};
#endif