from jinja2 import Environment, FileSystemLoader
import sys, json

fpm = sys.argv[1]
tnafp = json.loads(sys.argv[2])

if (len(tnafp.keys()) > 0):

    environment = Environment(loader=FileSystemLoader("../accel_library"), trim_blocks=True)

    template = environment.get_template("tnafp.fpm")

    tnafp['config']['fpm'] = fpm

    content = template.render(fpms=tnafp)

    fpm_src_path = "./" + fpm + "/"

    fpm_src = "tnafpm" + "." + fpm[3:] + ".bpf.c"

    with open(fpm_src_path + fpm_src, mode="w", encoding="utf-8") as fpsrc:
        fpsrc.write(content)
