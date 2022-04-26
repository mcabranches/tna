#ifndef USER_UTIL_H
#define USER_UTIL_H

#include <bpf/libbpf.h>

struct tna_interface {
	int ifindex;
	int master_index;
	uint8_t op_state;
	char ifname[16];
};


namespace util {

    static int uninstall_xdp(int ifindex, int flags)
    {
	    bpf_xdp_attach(ifindex, -1, flags, NULL);
	    return 1;
    }

    static int install_xdp(struct bpf_program *xdp_prog, int ifindex, int xdp_flags)
    {	
	    int bpf_prog_fd = bpf_program__fd(xdp_prog);

	    if (bpf_xdp_attach(ifindex, bpf_prog_fd, xdp_flags, NULL) < 0) {
			printf("Error linking fd to xdp with offload flags\n");
			return -1;
	    }
	    else {
		    printf("XDP program loaded\n");
	    }

	return 0;
    }
}

#endif