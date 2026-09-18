#!/bin/bash
#
# Control script for eBPF program to do Load PDU Receive Coalescing (LPRC) for OB-UDPST
#
# Load one instance of eBPF program (with common memory and state info) and attach to one or more interfaces
#
# NOTE: Superuser privilege (sudo) is required
# ---------------------------------------------------------------------------------------------------------------
#
xdpmode="xdp"		# Modes: xdpgeneric, xdpdrv, xdpoffload, or xdp (attempts xdpdrv, fallback to xdpgeneric)
progname="udpst_lprc"	# eBPF program name

#
# Validate parameters
#
if [ ${#} -eq 0 ]; then
	echo "Expecting: install <iface1> [iface2]..."
	echo "           remove <iface1> [iface2]..."
	echo "           show"
	exit
fi
interfaces="${*:2}" # List of interfaces passed as parameters 2 - N

#
# Execute command
#
bpffs="/sys/fs/bpf"			# BPF Filesystem (mount point)
mapdir="${bpffs}/${progname}_maps"	# Program subdirectory for pinned maps
if [ "${1}" == "install" ]; then
	if [ -z "${interfaces}" ]; then
		echo "Error: Interface list not provided"
		exit
	fi

	#
	# Load program if not already loaded
	#
	bpftool prog show pinned ${bpffs}/${progname} >/dev/null 2>&1
	if [ ${?} -ne 0 ]; then
		#
		# Assume path to eBPF program is same as this script (i.e., in the same directory)
		#
		progpath="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

		echo "Loading ${progname}..."
		mkdir -p $mapdir
		if [ ${?} -ne 0 ]; then
			exit
		fi
		bpftool prog load "${progpath}/${progname}.o" ${bpffs}/${progname} pinmaps ${mapdir}
	fi

	#
	# Attach program to interfaces
	#
	for intf in ${interfaces}; do
		echo "Attaching ${progname} to ${intf}..."
		bpftool net attach ${xdpmode} pinned ${bpffs}/${progname} dev ${intf}
	done

elif [ "${1}" == "remove" ]; then
	if [ -z "${interfaces}" ]; then
		echo "Error: Interface list not provided"
		exit
	fi

	#
	# Detach program from interfaces (skip unload if a detach fails)
	#
	for intf in ${interfaces}; do
		echo "Detaching ${progname} from ${intf}..."
		bpftool net detach ${xdpmode} dev ${intf}
		if [ ${?} -ne 0 ]; then
			exit
		fi
	done

	#
	# Unload program if all interfaces are detached
	#
	xdpintf=$(bpftool net show | sed -n '/^xdp:/{n;p;q}')
	if [ -z "$xdpintf" ]; then
		echo "Unloading ${progname}..."
		rm -f ${bpffs}/${progname}
		rm -rf ${mapdir}
	else
		echo "Error: Unable to unload ${progname}, interfaces are still attached"
	fi

elif [ "${1}" == "show" ]; then
	#
	# Show loaded program and interface attachments
	#
	echo "Showing program ${progname}..."
	bpftool prog show name ${progname}
	bpftool map dump name ${progname:0:8}.rodata | sed -n '/"version"/s/^[ \t]*//p'
	echo ""
	echo "Showing attached interfaces..."
	bpftool net show | sed -e '/tc:/,$d'
else
	echo "Error: Unknown command"
	exit
fi
# ---------------------------------------------------------------------------------------------------------------
