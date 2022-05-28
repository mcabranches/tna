#ifndef TNABR_H
#define TNABR_H

#include <bpf/bpf.h>
#include "util.h"
#include "xdp_brfdb.skel.h"


class Tnabr {
	public:
		Tnabr(int flags) 
		{
			if (flags < 0)
				throw std::invalid_argument("tnabr: invalid xdp flags");
			else
				_flags = flags;

			load_bpf();
		}

		Tnabr(void)
		{
			load_bpf();
		}

		~Tnabr(void) 
		{
			destroy_tnabr();
        }

		unordered_map<string, struct tna_bridge> tnabrs;

		int load_bpf(void) 
		{
			/* Load and verify BPF application */
			skel = xdp_brfdb_bpf__open();
			if (!skel) {

				throw std::runtime_error("Failed to open xdp_brfdb skel\n");

				return -1;
			}

			int err = xdp_brfdb_bpf__load(skel);
			if (err) {

				throw std::runtime_error("Failed to load and verify BPF skeleton\n");

				destroy_tnabr();
				return -2;
			}
			else 
				return 0;
		}

		int add_tna_bridge(struct tna_bridge tnabridge) 
		{
			tnabrs[tnabridge.brname] = tnabridge;

			cout << "Created tna bridge: " << tnabridge.brname << endl;

			return 0;
		}

		int get_tna_bridges(void) 
		{
			unordered_map<string, struct tna_bridge>::iterator it;

			cout << "Available TNA bridges: " << endl;

			for (it = tnabrs.begin(); it != tnabrs.end(); ++it)
        		cout << it->first << endl;

			return 0;
		}

		int add_if_tna_bridge(struct tna_bridge tnabridge, struct tna_interface tnainterface) 
		{

			cout << "Adding interface " << tnainterface.ifname << " to TNA bridge " << tnabridge.brname << endl;

			tnabrs[tnabridge.brname].brifs[tnainterface.ifname] =  tnainterface; //push_back(tnainterface);

			if ((tnabridge.op_state_str == "up") && (tnainterface.op_state_str == "up"))
				install_xdp_tnabr(tnainterface);

			return 0;
		}

		int remove_if_tna_bridge(struct tna_bridge tnabridge, struct tna_interface tnainterface) 
		{
			unordered_map<string, struct tna_interface>::iterator it;

			cout << "Removing interface " << tnainterface.ifindex << " from TNA bridge " << tnabridge.brname << endl;
			
			for (it = tnabrs[tnabridge.brname].brifs.begin(); it != tnabrs[tnabridge.brname].brifs.end(); ++it) {
        		if (it->second.ifname == tnainterface.ifname) {
					tnabrs[tnabridge.brname].brifs.erase(it->first);
					break;
				}
			}

			uninstall_xdp_tnabr(tnainterface);

			return 0;
		}

		int get_br_tna_interfaces(struct tna_bridge tnabridge) 
		{
			unordered_map<string, struct tna_interface>::iterator it;

			cout << "Available interfaces in TNA bridge " << tnabridge.brname << endl;

			for (it = tnabrs[tnabridge.brname].brifs.begin(); it != tnabrs[tnabridge.brname].brifs.end(); ++it)
				cout << "ifname: " << it->second.ifname << endl;

			return 0;
		}

		int accel_tna_bridge(struct tna_bridge tnabridge) 
		{
			if (tnabridge.op_state_str == "up") {
				unordered_map<string, struct tna_interface>::iterator it;
				for (it = tnabrs[tnabridge.brname].brifs.begin(); it != tnabrs[tnabridge.brname].brifs.end(); ++it) {

					//cout << "Installing XDP tnabr accel on ifname: " << it->ifname << endl;

					map_fd = bpf_map__fd(skel->maps.tx_port);

					if ((bpf_map_update_elem(map_fd, &it->second.ifindex, &it->second.ifindex, BPF_ANY)) != 0)
						cout << "Could not update redirect map contents ..." << endl;

					if (it->second.op_state_str == "up")
						install_xdp_tnabr(it->second);
				}
			}
			return 0;
		}

		int destroy_tnabr(void) 
		{
			_destroy_tnabr();
			return 0;
		}

		int install_xdp_tnabr(struct tna_interface interface)
		{
			//if (interface.xdp_set)
			//	return 0;

			int err = util::install_xdp(skel->progs.xdp_br_main_0, interface.ifindex, _flags);

			if (err < 0) {

				throw std::runtime_error("Failed to install tnabr code\n");

				uninstall_xdp_tnabr(interface);
			}

			cout << "Installing XDP tnabr accel on interface: " << interface.ifindex << endl;

			return err;
		}

		int uninstall_xdp_tnabr(struct tna_interface interface) 
		{

			cout << "Uninstalling XDP tnabr accel on interface: " << interface.ifindex << endl;

			util::uninstall_xdp(interface.ifindex, _flags);

			return 0;
		}

	private:
		int ret;
		struct xdp_brfdb_bpf *skel;
		int _ifindex;
		int _flags = XDP_FLAGS_HW_MODE; /* default */
		int map_fd;

		int _destroy_tnabr(void)
		{
			unordered_map<string, struct tna_bridge>::iterator br_it;
			unordered_map<string, struct tna_interface>::iterator if_it;

			for (br_it = tnabrs.begin(); br_it != tnabrs.end(); ++br_it) {
				for (if_it = br_it->second.brifs.begin(); if_it != br_it->second.brifs.end(); ++if_it) {
					uninstall_xdp_tnabr(if_it->second);
				}
			}
			xdp_brfdb_bpf__destroy(skel);

			return 0;
		}

};
#endif