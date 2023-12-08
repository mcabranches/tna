/* TNA's fast path deployer */

#ifndef TNAFPD_H
#define TNAFPD_H

//#include <bpf/bpf.h>
#include "util.h"
#include "tnafp.skel.h"
#include "tnafp.tc.skel.h"


class Tnafpd {
	public:
		Tnafpd(int flags, int fpm_hook) 
		{
			cout << "Initializing tnafpd" << endl;
			if (flags < 0)
				throw std::invalid_argument("tnafpd: invalid xdp flags");
			else
				_flags = flags;
			
			_fpm_hook = fpm_hook;
		}

		Tnafpd(void)
		{
			cout << "Initializing tnafpd" << endl;
			_fpm_hook = FPM_TC; //default
		}

		int set_dp_type(string dp_type) 
		{
			if (dp_type == "xdp_drv") {
				_fpm_hook = FPM_XDP;
				_flags = XDP_FLAGS_DRV_MODE;
			}
			else if (dp_type == "xdp") {
				_fpm_hook = FPM_XDP;
			}
			else if (dp_type == "tc") {
				_fpm_hook = FPM_TC;
			}
			else
				return 0;
			
			return 1;
		}

		string get_fpm_hook(void)
		{
			if (_fpm_hook == FPM_XDP)
				return "FPM_XDP";

			if (_fpm_hook == FPM_TC)
				return "FPM_TC";

			else
				return "invalid";		
		}

		int load_bpf() 
		{
			if (_fpm_hook == FPM_XDP)
				load_bpf_xdp();

			if (_fpm_hook == FPM_TC)
				load_bpf_tc();

			return 0;
		}

		int load_bpf_fpm(struct tna_fpd *_tna_fpd, string fpm)
		{

			string fpm_comp_cmd = "cd ./src/fp_assembler/" + fpm + "/ && make >> /dev/null";
			//Unload previous data path
			if (_tna_fpd->fpm_fd > 0) {
				bpf_object__close(_tna_fpd->fpm_bpf_obj);
			}
			//compile new data path
			system(fpm_comp_cmd.c_str());

			if (bpf_prog_load_xattr(&_tna_fpd->fpm_prog_load_attr, &_tna_fpd->fpm_bpf_obj, &_tna_fpd->fpm_fd))
				throw std::runtime_error("load_xdp_program: cannot load object file");
			
			if (_tna_fpd->fpm_fd < 1)
				throw std::runtime_error("load_xdp_program: invalid program fd");

			_tna_fpd->fpm_dev_map = bpf_object__find_map_by_name(_tna_fpd->fpm_bpf_obj, "tx_port");

			_tna_fpd->fpm_dev_map_fd = bpf_map__fd(_tna_fpd->fpm_dev_map);

			return 0;

		}

		void add_tna_fpd(Tnaodb* tnaodb)
		{
			_add_tna_fpd(tnaodb);
		}

		int destroy_tnafp(void) 
		{
			_destroy_tnafp();
			return 0;
		}

		int deploy_tnafp(Tnaodb* tnaodb)
		{
			unordered_map<string, struct tna_bridge>::iterator br_it;
            unordered_map<string, struct tna_interface *>::iterator if_it;
			//process bridges
			for (br_it = tnaodb->tnabr->tnabrs.begin(); br_it != tnaodb->tnabr->tnabrs.end(); ++br_it) {

                //process bridge interfaces
                for (if_it = br_it->second.brifs.begin(); if_it !=  br_it->second.brifs.end(); ++if_it) {
                    if (if_it->second->op_state_str == "up") {                        
						cout << "Installing tnabr" << endl;
						if ((!tnaodb->tnaifs[if_it->second->ifname].fpm_set) && (tnaodb->tnaifs[if_it->second->ifname].ref_cnt > 0)) {
		 					install_tnafp(if_it->second);
							load_bpf_fpm(tnaodb->tnafpd["tnabr"], "tnabr");
							deploy_tnafpm(tnaodb->tnafpd["tnabr"], if_it->second);
						}
                    }

                } 

            }

            //process router interfaces (we have only one router)
            for (if_it = tnaodb->tnartr->tnartr.rtrifs.begin(); if_it != tnaodb->tnartr->tnartr.rtrifs.end(); ++if_it) {
                 if (if_it->second->op_state_str == "up") {				   
				    cout << "Installing tnartr" << endl;
					if ((!tnaodb->tnaifs[if_it->second->ifname].fpm_set) && (tnaodb->tnaifs[if_it->second->ifname].ref_cnt > 0)) {
						install_tnafp(if_it->second);
						load_bpf_fpm(tnaodb->tnafpd["tnartr"], "tnartr");
						deploy_tnafpm(tnaodb->tnafpd["tnartr"], if_it->second);
					}
                 }
            }

			return 0;
		}

		int deploy_tnafpm(struct tna_fpd *_tna_fpd, struct tna_interface *interface)
		{
			//12/02/2023 to support different dps use the index of the interface
			//as the index on the jmp_tbl
			int jmp_tbl_fd = 0;
			int idx = interface->ifindex;
			if (_fpm_hook == FPM_XDP)
				jmp_tbl_fd = bpf_map__fd(skel->maps.jmp_table);
			if (_fpm_hook == FPM_TC)
				jmp_tbl_fd = bpf_map__fd(skel_tc->maps.jmp_table);

			if (bpf_map_update_elem(jmp_tbl_fd, &idx, &_tna_fpd->fpm_fd, BPF_ANY) < 0)
				cout << "Could not update jmp_table map contents ... " << endl;
			if (bpf_map_update_elem(_tna_fpd->fpm_dev_map_fd, &idx, &idx, BPF_ANY) < 0)
				cout << "Could not update tx_port map contents ... " << endl;	
			
			return 0;
		}

		int clean_tnafp(struct Tnaodb *tnaodb)
		{
			unordered_map<string, struct tna_interface>::iterator it;

			for (it = tnaodb->tnaifs.begin(); it != tnaodb->tnaifs.end(); ++it) {
				if (it->second.fpm_set)
					uninstall_tnafp(&it->second);
			}
			destroy_tnafp();
		}

		int install_tnafp(struct tna_interface *interface)
		{
			int err;
			if (interface->type == "bridge")
				return 0;

			if (interface->fpm_set == 0) {
				
				cout << "Installing tnafp accel on interface: " << interface->ifindex << endl;

				if (_fpm_hook == FPM_XDP)
					err = util::install_xdp(skel->progs.xdp_tna_main_0, interface->ifindex, _flags);

				if (_fpm_hook == FPM_TC)
					err = util::install_tc(skel_tc->progs.tc_tna_main_0, interface->ifindex, _flags);

				if (err < 0) {

					throw std::runtime_error("Failed to install tnabr code\n");

					uninstall_tnafp(interface);
				}
				interface->fpm_set = 1;
			}

			return err;
		}

		int uninstall_tnafp(struct tna_interface *interface) 
		{
			if (interface->fpm_set == 1) {
				cout << "Uninstalling tnafp accel on interface: " << interface->ifindex << endl;

				if (_fpm_hook == FPM_XDP)
					util::uninstall_xdp(interface->ifindex, _flags);

				if (_fpm_hook == FPM_TC)
					util::uninstall_tc(interface->ifindex, _flags);

				interface->fpm_set = 0;
			}

			return 0;
		}

	private:
		int ret;
		struct tnafp_bpf *skel;
		struct tnafp_tc_bpf *skel_tc;
		int _fpm_hook;
		int _ifindex;
		int _flags = XDP_FLAGS_SKB_MODE; /* default */
		int map_fd;
		struct tna_fpd tna_fpd_tnartr;
		struct tna_fpd tna_fpd_tnabr;
		/* struct tna_fpd tna_fpd_tnaipvs; */


		int load_bpf_xdp() 
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

		int load_bpf_tc() 
		{
			/* Load and verify BPF application */
			skel_tc = tnafp_tc_bpf__open();
			if (!skel_tc) {

				throw std::runtime_error("Failed to open xdpfp skel\n");

				return -1;
			}

			int err = tnafp_tc_bpf__load(skel_tc);
			if (err) {

				throw std::runtime_error("Failed to load and verify BPF skeleton\n");

				destroy_tnafp();
				return -2;
			}
			else 
				return 0;
		}

		void _add_tna_fpd(Tnaodb* tnaodb)
		{
			tnaodb->tnafpd["tnabr"] = &tna_fpd_tnabr;
			tnaodb->tnafpd["tnartr"] = &tna_fpd_tnartr;

			//init tnabr fpd
			if (_fpm_hook == FPM_XDP) {
				tnaodb->tnafpd["tnabr"]->fpm_prog_load_attr = {
					.file = "./build/.output/tnafpm.br.bpf.o",
					.prog_type = BPF_PROG_TYPE_XDP
				};
			}

			if (_fpm_hook == FPM_TC) {
				tnaodb->tnafpd["tnabr"]->fpm_prog_load_attr = {
					.file = "./build/.output/tnafpm.br.bpf.o",
					.prog_type = BPF_PROG_TYPE_SCHED_CLS
				};
			}


			tnaodb->tnafpd["tnabr"]->fpm_bpf_obj = nullptr;
			tnaodb->tnafpd["tnabr"]->fpm_dev_map_fd = 0;
			tnaodb->tnafpd["tnabr"]->fpm_fd = 0;

			//init tnartr fpd

			if (_fpm_hook == FPM_XDP) {
				tnaodb->tnafpd["tnartr"]->fpm_prog_load_attr = {
					.file = "./build/.output/tnafpm.rtr.bpf.o",
					.prog_type = BPF_PROG_TYPE_XDP
				};
			}

			if (_fpm_hook == FPM_TC) {
				tnaodb->tnafpd["tnartr"]->fpm_prog_load_attr = {
					.file = "./build/.output/tnafpm.rtr.bpf.o",
					.prog_type = BPF_PROG_TYPE_SCHED_CLS
				};
			}
			tnaodb->tnafpd["tnartr"]->fpm_bpf_obj = nullptr;
			tnaodb->tnafpd["tnartr"]->fpm_dev_map_fd = 0;
			tnaodb->tnafpd["tnartr"]->fpm_fd = 0;
		}


		int _destroy_tnafp(void)
		{
			if (_fpm_hook == FPM_XDP)
				tnafp_bpf__destroy(skel);

			if (_fpm_hook == FPM_TC)
				tnafp_tc_bpf__destroy(skel_tc);

			return 0;
		}
};
#endif
