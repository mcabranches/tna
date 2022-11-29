/* TNA's fast path deployer */

#ifndef TNAFPD_H
#define TNAFPD_H

#include <bpf/bpf.h>
#include "util.h"
#include "tnafp.skel.h"


class Tnafpd {
	public:
		Tnafpd(int flags) 
		{
			cout << "Initializing tnafpd" << endl;
			if (flags < 0)
				throw std::invalid_argument("tnafpd: invalid xdp flags");
			else
				_flags = flags;

			load_bpf();
		}

		Tnafpd(void)
		{
			load_bpf();
		}

		~Tnafpd(void) 
		{
			destroy_tnafp();
        }

		int load_bpf(void) 
		{
			/* Load and verify BPF application */
			skel = tnafp_bpf__open();
			if (!skel) {

				throw std::runtime_error("Failed to open xdpfp skel\n");

				return -1;
			}

			int err = tnafp_bpf__load(skel);
			if (err) {

				throw std::runtime_error("Failed to load and verify BPF skeleton\n");

				destroy_tnafp();
				return -2;
			}
			else 
				return 0;
		}

		int load_bpf_fpm(void) 
		{

			if (fpm_fd > 0)
				return 1;

			if (bpf_prog_load_xattr(&fpm_prog_load_attr, &fpm_bpf_obj, &fpm_fd))
				throw std::runtime_error("load_xdp_program: cannot load object file");
			
			if (fpm_fd < 1)
				throw std::runtime_error("load_xdp_program: invalid program fd");

			fpm_dev_map = bpf_object__find_map_by_name(fpm_bpf_obj, "tx_port");

			fpm_dev_map_fd = bpf_map__fd(fpm_dev_map);

			return 0;

		}

		int destroy_tnafp(void) 
		{
			_destroy_tnafp();
			return 0;
		}

		int deploy_tnafp(struct Tnaodb *tnaodb)
		{
			unordered_map<string, struct tna_interface>::iterator it;
			int idx;
			load_bpf_fpm();
			deploy_tnafpm();

			for (it = tnaodb->tnaifs.begin(); it != tnaodb->tnaifs.end(); ++it) {
				if ((!it->second.xdp_set) && it->second.ref_cnt > 0) {
					install_tnafp(&it->second);
					if (bpf_map_update_elem(fpm_dev_map_fd, &it->second.ifindex, &it->second.ifindex, BPF_ANY) < 0)
						cout << "Could not update tx_port map contents ... " << endl;

				}
			}
			return 0;
		}

		int deploy_tnafpm(void)
		{
			int idx = 0;
			int jmp_tbl_fd = bpf_map__fd(skel->maps.jmp_table);

			if (bpf_map_update_elem(jmp_tbl_fd, &idx, &fpm_fd, BPF_ANY) < 0)
				cout << "Could not update jmp_table map contents ... " << endl;
			
			return 0;
		}

		int clean_tnafp(struct Tnaodb *tnaodb)
		{
			unordered_map<string, struct tna_interface>::iterator it;

			for (it = tnaodb->tnaifs.begin(); it != tnaodb->tnaifs.end(); ++it) {
				if (it->second.xdp_set)
					uninstall_tnafp(&it->second);
			}
		}

		int install_tnafp(struct tna_interface *interface)
		{
			int err;
			if (interface->xdp_set == 0) {
				cout << "Installing XDP tnafp accel on interface: " << interface->ifindex << endl;

				err = util::install_xdp(skel->progs.xdp_tna_main_0, interface->ifindex, _flags);

				if (err < 0) {

					throw std::runtime_error("Failed to install tnabr code\n");

					uninstall_tnafp(interface);
				}
				interface->xdp_set = 1;
			}

			return err;
		}

		int uninstall_tnafp(struct tna_interface *interface) 
		{
			if (interface->xdp_set == 1) {
				cout << "Uninstalling XDP tnabr accel on interface: " << interface->ifindex << endl;

				util::uninstall_xdp(interface->ifindex, _flags);

				interface->xdp_set = 0;
			}

			return 0;
		}

	private:
		int ret;
		struct tnafp_bpf *skel;
		int _ifindex;
		int _flags = XDP_FLAGS_SKB_MODE; /* default */
		int map_fd;
		struct bpf_prog_load_attr fpm_prog_load_attr = {
			.file = "./build/.output/tnafpm.bpf.o",
			.prog_type = BPF_PROG_TYPE_XDP
		};
		struct bpf_object *fpm_bpf_obj = nullptr;
		struct bpf_program *fpm_bpf_prog;
		struct bpf_map *fpm_dev_map; 
		int fpm_dev_map_fd = 0;
		int fpm_fd = 0;	

		int _destroy_tnafp(void)
		{
			tnafp_bpf__destroy(skel);

			return 0;
		}
};
#endif
