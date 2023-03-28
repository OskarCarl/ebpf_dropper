import argparse
import os, subprocess, shutil

TCP = 0x06
UDP = 0x11

def ip_to_int(ip):
    s = ip.split(".")
    sum = 0
    for i, b in enumerate(s):
        sum += int(b) << ((3-i)*8)
    return sum

def runElevated(cmdToExec):
    if os.getuid() != 0:
        helperPrograms = ['doas', 'sudo']
        for h in helperPrograms:
            if shutil.which(h):
                expandedCmd = [shutil.which(h)] + cmdToExec
                if args.v:
                    print(' '.join(expandedCmd))
                p = subprocess.Popen(expandedCmd)
                p.wait(timeout=10)
                if p.returncode != 0:
                    print("Encountered an error when running '{}'".format(' '.join(expandedCmd)))
                    exit(p.returncode)
                return
        print("Must be root or have one of {} to do this".format(helperPrograms))
        exit(2)

parser = argparse.ArgumentParser()
parser.add_argument("--sequence", help="drop a sequence of packets (numbers separated by commas)", default="")
parser.add_argument("--gemodel", help="use a gilbert-elliott model", action="store_true")
parser.add_argument("-P", help="loss rate or p gemodel parameter (float) (0 <= p <= 100)", type=float, default=0)
parser.add_argument("-R", help="r gemodel parameter (float) (0 <= r <= 100)", type=float, default=100)
parser.add_argument("-K", help="k gemodel parameter (float) (0 <= k <= 100)", type=float, default=100)
parser.add_argument("-H", help="h gemodel parameter (float) (0 <= h <= 100)", type=float, default=0)
parser.add_argument("-f", help="filename to write the compiled eBPF bytecode into (default ebpf_dropper.o)", default="ebpf_dropper.o")
parser.add_argument("-v", help="verbose mode", action="store_true")
parser.add_argument("--ips", help="pair of IPv4 addresses to watch (separated by a comma), a packet must have both of "
                                "these addresses in either source or destination in order to be considered by the "
                                "dropper")
parser.add_argument("--port", help="port (tcp or udp), a packet must have this value either for the source or destination"
                                 "port in order to be considered by the dropper", type=int, default=443)
parser.add_argument("--udp", help="if set, monitor UDP packets instead of TCP", action="store_true")
parser.add_argument("--seed", help="prng seed (int)", type=int, default=42)
parser.add_argument("--headers", help="directory containing the uapi linux headers needed to compile the dropper",
                    default="/usr/lib/modules/{}/build/include/".format(os.uname().release))
parser.add_argument("--attach", help="specifies the interface on which to attach the generated file",
                    default=None)
parser.add_argument("--attach-ingress", help="if set and the --attach option is used, the dropper will be attached in"
                                             "ingress instead of egress", action="store_true")
parser.add_argument("--clean", help="clean everything instead of compiling and attaching", action="store_true")


args = parser.parse_args()

sequence = args.sequence
gemodel = args.gemodel

if sequence and gemodel:
    raise Exception("Either gemodel or sequence but not both")

if args.clean:
    if os.path.exists(args.f):
        os.remove(args.f)
    runElevated(["tc", "qdisc", "del", "dev", args.attach, "clsact"])
    exit()

clang_args = []
if gemodel:
    clang_args += [
        "-DGEMODEL=1", "-DDROP_SEQUENCE=0",
        "-DGEMODEL_P_PERCENTS={}".format(args.P), "-DGEMODEL_R_PERCENTS={}".format(args.R),
        "-DGEMODEL_K_PERCENTS={}".format(args.K), "-DGEMODEL_H_PERCENTS={}".format(args.H),
        "-DSEED={}".format(args.seed)
        ]
elif sequence:
    clang_args += ["-DGEMODEL=0", "-DDROP_SEQUENCE=1", "-DSEQUENCE=\\{{{}\\}}".format(sequence)]
else:
    clang_args += ["-DPROBA_percents={}".format(args.P)]

if args.ips:
    ips = args.ips.split(",")
    clang_args += ["-DIP1_TO_DROP={}".format(ip_to_int(ips[0])), "-DIP2_TO_DROP={}".format(ip_to_int(ips[1]))]

clang_args += ["-DPORT_TO_WATCH={}".format(args.port), "-DPROTOCOL_TO_WATCH={}".format(UDP if args.udp else TCP),
    "-I{}".format(args.headers)]

compile_cmd = ["clang", "-O2", "-g", "-D__KERNEL__", "-D__ASM_SYSREG_H", "-Wno-unused-value", "-Wno-pointer-sign", "-fno-stack-protector",
                "-Wno-compare-distinct-pointer-types"] + clang_args + ["-emit-llvm", "-c", "ebpf_dropper.c", "-o", "-"]
llc_command = ["llc", "-march=bpf", "-filetype=obj", "-o", args.f]

if args.v:
    print(' '.join(compile_cmd + ['|'] + llc_command))

with subprocess.Popen(compile_cmd, stdout=subprocess.PIPE) as clang:
    with subprocess.Popen(llc_command, stdin=clang.stdout) as llc:
        llc.communicate()
        clang.wait()
        if clang.returncode != 0 or llc.returncode != 0:
            print("Encountered an error during compilation.")
            print("  clang returncode: {}".format(clang.returncode))
            print("  llc returncode: {}".format(llc.returncode))
            exit(clang.returncode + llc.returncode)

if args.attach:
    runElevated(["tc", "qdisc", "replace", "dev", args.attach, "clsact"])
    direction = "ingress" if args.attach_ingress else 'egress'
    runElevated(["tc", "filter", "replace", "dev", args.attach, direction, "bpf", "obj", args.f, "section", "action", "direct-action"])
