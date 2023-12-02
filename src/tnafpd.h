/* TNA's fast path deployer */

#ifndef TNAFPD_H
#define TNAFPD_H

//#include <bpf/bpf.h>
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

			//load_bpf(struct Tnaodb *tnaodb);
		}

		Tnafpd(void)
		{
		 	//load_bpf();
		}

		// ~Tnafpd(void) 
		// {
		// 	destroy_tnafp();
        // }

		int load_bpf() 
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

		//int load_bpf_fpm(void)
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

			cout << "_tna_fpd->fpm_dev_map_fd " << _tna_fpd->fpm_dev_map_fd << endl;
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
                        //tafpd.deploy_tnafp(if_it->second, "tnabr") //TODO: update this function
                        
						cout << "Installing tnabr" << endl;
						if ((!if_it->second->xdp_set) && (if_it->second->ref_cnt > 0)) {
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
					 //tafpd.deploy_tnafp(if_it->second, "tnartr") //TODO: update this function
				   
				    cout << "Installing tnartr" << endl;
					if ((!if_it->second->xdp_set) && (if_it->second->ref_cnt > 0)) {
						install_tnafp(if_it->second);
						load_bpf_fpm(tnaodb->tnafpd["tnartr"], "tnartr");
						deploy_tnafpm(tnaodb->tnafpd["tnartr"], if_it->second);
					}
                    //tafpd.deploy_tnafp(if_it->second, "tnartr") //TODO: update this function

                 }
            }

			// unordered_map<string, struct tna_interface>::iterator it;
			// int idx;
			//load_bpf_fpm(&tnaodb->tnafpd["tnabr"]);
			//load_bpf_fpm(&tnaodb->tnafpd["tnartr"]);
			//load_bpf_fpm(&tnaodb->tnafpd["tnaipt"]);
			// deploy_tnafpm();

			// for (it = tnaodb->tnaifs.begin(); it != tnaodb->tnaifs.end(); ++it) {
			// 	if ((!it->second.xdp_set) && (it->second.ref_cnt > 0)) {
			// 		install_tnafp(&it->second);
			// 	}
			// 	if (it->second.ref_cnt > 0)
			// 		if (bpf_map_update_elem(fpm_dev_map_fd, &it->second.ifindex, &it->second.ifindex, BPF_ANY) < 0)
			// 			cout << "Could not update tx_port map contents ... " << endl;
			// }
			return 0;
		}

		int deploy_tnafpm(struct tna_fpd *_tna_fpd, struct tna_interface *interface)
		{
			//12/02/2023 to support different dps use the index of the interface
			//as the index on the jmp_tbl
			int idx = interface->ifindex;
			int jmp_tbl_fd = bpf_map__fd(skel->maps.jmp_table);

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
				if (it->second.xdp_set)
					uninstall_tnafp(&it->second);
			}
			destroy_tnafp();
		}

		int install_tnafp(struct tna_interface *interface)
		{
			int err;
			if (interface->type == "bridge")
				return 0;

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
		// struct bpf_prog_load_attr fpm_prog_load_attr = {
		// 	.file = "./build/.output/tnafpm.bpf.o",
		// 	.prog_type = BPF_PROG_TYPE_XDP
		// };
		// struct bpf_object *fpm_bpf_obj = nullptr;
		// struct bpf_program *fpm_bpf_prog;
		// struct bpf_map *fpm_dev_map;
		// int fpm_dev_map_fd = 0;
		// int fpm_fd = 0;	
		struct tna_fpd tna_fpd_tnartr;
		struct tna_fpd tna_fpd_tnabr;
		/* struct tna_fpd tna_fpd_tnaipvs; */

		void _add_tna_fpd(Tnaodb* tnaodb)
		{
			tnaodb->tnafpd["tnabr"] = &tna_fpd_tnabr;
			tnaodb->tnafpd["tnartr"] = &tna_fpd_tnartr;
			/* tnaodb->tnafpd["tnaipvs"] = &tna_fpd_tnaipvs; */

			//init tnabr fpd
			tnaodb->tnafpd["tnabr"]->fpm_prog_load_attr = {
				.file = "./build/.output/tnafpm.br.bpf.o",
		 		.prog_type = BPF_PROG_TYPE_XDP
			};
			tnaodb->tnafpd["tnabr"]->fpm_bpf_obj = nullptr;
			tnaodb->tnafpd["tnabr"]->fpm_dev_map_fd = 0;
			tnaodb->tnafpd["tnabr"]->fpm_fd = 0;

			//init tnartr fpd
			tnaodb->tnafpd["tnartr"]->fpm_prog_load_attr = {
				.file = "./build/.output/tnafpm.rtr.bpf.o",
		 		.prog_type = BPF_PROG_TYPE_XDP
			};
			tnaodb->tnafpd["tnartr"]->fpm_bpf_obj = nullptr;
			tnaodb->tnafpd["tnartr"]->fpm_dev_map_fd = 0;
			tnaodb->tnafpd["tnartr"]->fpm_fd = 0;
		}


		int _destroy_tnafp(void)
		{
			tnafp_bpf__destroy(skel);

			return 0;
		}
};
#endif
