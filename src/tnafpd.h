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

		int destroy_tnafp(void) 
		{
			_destroy_tnafp();
			return 0;
		}

		int deploy_tnafp(struct Tnaodb *tnaodb)
		{
			unordered_map<string, struct tna_interface>::iterator it;

			for (it = tnaodb->tnaifs.begin(); it != tnaodb->tnaifs.end(); ++it) {
				if (!it->second.xdp_set)
					install_tnafp(&it->second);
			}
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

		//int install_xdp_tnabr(struct tna_interface *interface)
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

				/*map_fd = bpf_map__fd(skel->maps.tx_port);

				cout << "######### MAP FD " << map_fd << endl;
				int u = 1;
				//if ((bpf_map_update_elem(map_fd, (int *)interface->ifindex, (int *)interface->ifindex, BPF_ANY)) != 0) {
				if ((bpf_map_update_elem(map_fd, (int *)&u, (int *)&u, BPF_ANY)) != 0) {
					cout << "Could not update redirect map contents ..." << endl;

				}*/

				interface->xdp_set = 1;
				//tnainterfaces[interface->ifname] = *interface;
			}

			return err;
		}

		//int uninstall_xdp_tnabr(struct tna_interface *interface) 
		int uninstall_tnafp(struct tna_interface *interface) 
		{
			if (interface->xdp_set == 1) {
				cout << "Uninstalling XDP tnabr accel on interface: " << interface->ifindex << endl;

				util::uninstall_xdp(interface->ifindex, _flags);

				/*if ((bpf_map_delete_elem(map_fd, (int *) interface->ifindex)) != 0)
					cout << "Could not update redirect map contents ..." << endl;*/

				interface->xdp_set = 0;
				//tnainterfaces.erase(interface->ifname);
			}

			return 0;
		}

	private:
		int ret;
		struct tnafp_bpf *skel;
		int _ifindex;
		int _flags = XDP_FLAGS_SKB_MODE; /* default */
		int map_fd;
		//unordered_map<string, struct tna_interface> tnainterfaces; //m-> this propably should be in tnaotm (tnaodb)
		

		int _destroy_tnafp(void)
		{
			//unordered_map<string, struct tna_interface>::iterator it;

			//m-> should be this called tnaodb using a map defined on tnatm?
			//for (it = tnainterfaces.begin(); it != tnainterfaces.end(); ++it) {
			//	uninstall_tnafp(&it->second);
			//}
			tnafp_bpf__destroy(skel);

			return 0;
		}
};
#endif
