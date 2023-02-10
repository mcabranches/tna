from jinja2 import Environment, FileSystemLoader
import sys, json

fpms = []

tnafp = json.loads(sys.argv[1])

#get an ordered list of fpms based on their interdependencies
for fpm in tnafp.keys():
    if fpm == 'fpms':
        key = tnafp['fpms']
        fpms.append(key)

environment = Environment(loader=FileSystemLoader("../accel_library"), trim_blocks=True)

template = environment.get_template("tnafp.fpm")

content = template.render(fpms=tnafp)

with open("tnafpm.bpf.c", mode="w", encoding="utf-8") as fpsrc:
    fpsrc.write(content)
