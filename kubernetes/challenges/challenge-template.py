from jinja2 import Environment, FileSystemLoader
import argparse
import ast

environment = Environment(keep_trailing_newline=True, loader=FileSystemLoader("templates/"))

parser = argparse.ArgumentParser(description="Kubernetes challenge template")

parser.add_argument('name', metavar='name', type=str, nargs=1, help='Name of your challenge')
parser.add_argument('layer', metavar='layer', type=int, nargs=1, help='What layer your challenge runs on')
parser.add_argument('cpulimit', metavar='cpulimit', type=str, nargs=1, help='How much cpu your challenge needs (in mCores, ex "500m")')
parser.add_argument('memorylimit', metavar='memorylimit', type=str, nargs=1, help='How much memory your challenge needs (in Mi/Gi, ex "512Mi")')
parser.add_argument('ports', type=ast.literal_eval, help="Ports your container needs")
parser.add_argument('--instances', metavar='i', type=int, nargs=1, help='Your container should have a read-only filesystem')
parser.add_argument('--read-only', action=argparse.BooleanOptionalAction, help='Your container should have a read-only filesystem')

args = parser.parse_args()

name = args.name[0]
layer = args.layer[0]
cpu_limit = args.cpulimit[0]
memory_limit = args.memorylimit[0]
ports = args.ports
instances = args.instances[0] if args.instances is not None else 2
read_only = args.read_only

if layer not in {4, 7}:
    print("Only layer 4 or 7 services are supported.")

filename = "{name}.yaml".format(name=name)
template = None

if layer == 4:
    template = environment.get_template("l4-template.j2")

if layer == 7:
    template = environment.get_template("l7-template.j2")

context = {
    "name": name,
    "layer": layer,
    "cpuLimit": cpu_limit,
    "memoryLimit": memory_limit,
    "ports": ports,
    "instances": instances,
    "fs_read_only": read_only
}

with open (filename, mode="w", encoding="utf-8") as res:
    res.write(template.render(context)) 