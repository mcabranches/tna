from jinja2 import Environment, FileSystemLoader
import sys, json

fpms = []

tnafp = json.loads(sys.argv[1])

#get an ordered list of fpms based on their interdependencies
for fpm in tnafp.keys():
    if fpm == 'fpm1':
        key = tnafp['fpm1']
    else:
        key = tnafp[key]
    fpms.append(key)

environment = Environment(loader=FileSystemLoader("../accel_library"), trim_blocks=True)
template = environment.get_template("fpm1.fpm")

#content = template.render(fpms=tnafp)
#with open("../tnafp.bpf.c", mode="w", encoding="utf-8") as fpsrc:
#    fpsrc.write(content);
#    print(content)

#continue building the fast path
#for fpm in fpms:
template = environment.get_template("tnafp.fpm")
content = template.render(fpms=tnafp)
with open("tnafpm.bpf.c", mode="w", encoding="utf-8") as fpsrc:
    fpsrc.write(content);
