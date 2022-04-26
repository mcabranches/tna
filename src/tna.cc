#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <linux/if_link.h>
#include "tnabr.h"

int main(void)
{
    auto tnabr = Tnabr(3);

    tnabr.install_tnabr(3);
    std::cout <<"Starting TNA controller ..." <<  std::endl;

    while(true) { //controller's main loop
        sleep(1);
    }

    return 0;
}