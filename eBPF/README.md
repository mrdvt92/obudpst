# Load PDU Receive Coalescing (LPRC) via eBPF/XDP
This optional capability utilizes an eBPF (Extended Berkeley Packet Filter)
program and XDP (eXpress Data Path) to provide a significant performance
boost for received load traffic (whether client or server). It is intended
as the complementary optimization to GSO, which already provides a significant
performance boost for transmitted traffic.

Once loaded and attached to an interface, the eBPF program works by first
signaling to udpst at the start of each test that it should expect LPRC
"packed" datagrams instead of individual datagrams. Note, this is only
done for tests where the udpst instance would be receiving Load PDUs (i.e.,
clients doing downstream tests or servers servicing upstream tests).
The signaling is performed by intercepting the Test Activation PDU from
the interface and changing the ID before passing it up the protocol stack
for processing. When udpst sees this unique ID in the Test Activation PDU, it
knows to expect LPRC datagrams for this test. If verbose mode is enabled, a
confirmation message is also displayed
(`Local eBPF/XDP program signaled LPRC...`).

Subsequently, as each Load PDU is received for a flow, its arrival time,
ToS/Traffic Class, and Load PDU header are stored as a Receive Event. The
actual Load PDU is then dropped without any processing (or further processing,
depending on the XDP mode) by the protocol stack.

After enough Receive Events have accumulated, a subsequent Load PDU is
converted to an LPRC datagram where it is packed with Receive Events and
passed up the protocol stack for processing by udpst. With the metadata
and Load PDU headers, udpst then processes all the Receive Events as it
normally would for each previously received Load PDU. Currently, given the
size of a Receive Event, this allows one LPRC datagram to reduce receive-side
protocol processing by up to 36:1 when the `-T` option is used (or 30:1 when
it is not).

*Note: Jumbo sizes are supported with LPRC. However, similar to the GSO
optimization, IP fragmentation is not supported and will cause the test to
terminate.*

## Building and Installing
In addition to a standard development environment, the following may also
need to be installed (not a complete list):
```
clang
libbpf-dev (or libbpf-devel)
bpftool
```
Additionally, a simple shell script (`lprcctl.sh`) has been included to help
with loading the program into memory and attaching it to interfaces. For
example, specifying a single interface of `eno1`...
```
$ sudo ./lprcctl.sh install eno1
Loading udpst_lprc...
Attaching udpst_lprc to eno1...

$ sudo ./lprcctl.sh show
Showing program udpst_lprc...
109: xdp  name udpst_lprc  tag de804af5bcaefb2f  gpl
        loaded_at 2026-08-18T11:28:37-0400  uid 0
        xlated 4000B  jited 2220B  memlock 4096B  map_ids 22,23
        btf_id 169
"version": "v1.0.0"

Showing attached interfaces...
xdp:
eno1(2) generic id 109
```
Detaching and unloading the program is done similarly...
```
$ sudo ./lprcctl.sh remove eno1
Detaching udpst_lprc from eno1...
Unloading udpst_lprc...

$ sudo ./lprcctl.sh show
Showing program udpst_lprc...

Showing attached interfaces...
xdp:

```

## XDP (eXpress Data Path) Modes
There are three modes (and one convenience designation) available when
attaching an eBPF program to an interface.

- **xdpgeneric** (Generic / SKB Mode): Executes the eBPF program within the
kernel network stack after packet allocation (sk_buff). Offers universal driver
compatibility, but with only moderate performance acceleration.

- **xdpdrv** (Native / Driver Mode): Executes the eBPF program directly inside
the network interface driver's initial receive processing path before kernel
buffer allocation. Must be supported by the driver, but provides
higher-performance packet processing.

- **xdpoffload** (Offload Mode): Loads and executes the eBPF program directly
on supported SmartNIC hardware instead of the host CPU. Offers the highest
performance improvement, but is very limited in availability.

- **xdp** (Convenience Designation): This designation indicates that
**xdpdrv** should be attempted, but **xdpgeneric** is acceptable if it's not
supported.

_For a list of supported drivers and their modes see_
https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/#driver-support

*Note: During LPRC testing the use of **xdpgeneric** was shown to provide a
performance increase and CPU reduction extremely close to **xdpdrv**.
This is most likely due to the specific characteristics of the udpst load
traffic combined with the particular optimization done with LPRC. This provides
a huge operational advantage in that **xdpgeneric** can be utilized
regardless of whether the network driver provides native XDP support.*

## UDP Checksum Considerations
For IPv4, a UDP checksum is optional. Given that newly constructed LPRC
datagrams are never transmitted anywhere, only passed up the protocol stack,
the UDP checksum is disabled by default to reduce CPU processing. This is
controlled via the compilation flag `IPV4_UDP_CSUM` in the source file. When
set to `false` (the default), the UDP checksum field is zeroed, disabling its
use.

For IPv6, the UDP checksum is mandatory. However, if the Ethernet interface(s)
are already verifying the received UDP checksum as an offload function, this
additional CPU processing can also be avoided by setting `IPV6_UDP_CSUM` to
`false` (the default). In this scenario, a dummy non-zero value (0xFFFF) is
inserted to satisfy IPv6's non-zero UDP checksum requirement. Because the
originally received datagram was already checksum-validated by the NIC, it is
marked with `CHECKSUM_UNNECESSARY` so the protocol stack does not attempt to
validate the dummy value.

To view the receive checksum offload setting:
```
$ ethtool -k <iface> | grep rx-checksumming
```
To change the setting:
```
$ sudo ethtool -K <iface> rx on|off
```
*Note: Even when rx-checksumming shows as enabled by the kernel, if IPv6
tests will not run, the functionality may not be active due to an outdated
network driver (which may require updating).*

## Special Considerations for IPv6 and Jumbo Frames
In environments where jumbo frames are not currently in use (i.e., not
configured on the gateway router), explicit configuration of additional IPv6
settings may be required to utilize them on the host's local LAN.

Simply configuring a link's MTU to 9000 bytes can be insufficient for IPv6
because the kernel and host networking stack maintain Layer 3 IPv6 MTU state
independently from physical interface frame limits. Even when an interface
reports an MTU of 9000, external triggers such as ICMPv6 Router Advertisements
(RAs) from the gateway router can silently reset the kernel's L3 IPv6 MTU back
to 1500, causing the host to unexpectedly fragment IPv6 traffic.

To force a 9000-byte L3 IPv6 MTU on an interface, it may need to be set
explicitly and/or the processing of received ICMPv6 RAs may need to be
disabled (if RA MTU processing is not explicitly disabled). Note that the
disabling of ICMPv6 RAs may result in an IPv6 default route not getting
configured and possibly prevent other IPv6 addresses (other than the link-local
address) from being added to the interfaces.

After a 9000-byte MTU is configured on a system, the following commands can be
used to verify the correct values:
```
$ ip link show dev <iface>
$ sysctl net.ipv6.conf.<iface>.mtu
```

## Usage with AWS
The eBPF program was tested on an AWS EC2 (c8in.8xlarge) instance and attached
to the ENA driver with XDP in driver/native mode. However, a few operational
considerations arose during configuration. First, the Ethernet interface needed
to have its MTU reset from 9001 to 1500 due to the following limitation:
```
enp39s0: Failed to set xdp program, the current MTU (9001) is larger than the
maximum allowed MTU (3498) while xdp is on
```
This occurred because the ENA XDP configuration in use was subject to its
single-buffer maximum MTU (with 4-KB memory pages). Second, after this change,
the following was observed:
```
enp39s0: Failed to set xdp program, the Rx/Tx channel count should be at most
half of the maximum allowed channel count. The current queue count (32), the
maximal queue count (32)
```
For the ENA driver/version tested, the number of combined channels had to be
reduced to half or less of the maximum. Therefore, the combined channels were
reduced to half (16) via `sudo ethtool -L <iface> combined 16`.

After this point, the eBPF program could be attached in driver/native mode and
functioned as expected.

*Note: ENA Express and ENA Express UDP were not enabled during testing. It
appeared that, under heavy load, AWS’s Scalable Reliable Datagram (SRD)
protocol was unable to guarantee packet order, and as a result considerable
Load PDU reordering was observed.*

## Considerations for Older or Low-End Devices
As a sanity check, the eBPF program was tested on a Raspberry Pi 4. However,
it was not possible using the latest Raspberry Pi OS. Although technically the
kernel should have supported it, the issue appeared to be a result of how it
was built for distribution (i.e., `CONFIG_DEBUG_INFO_BTF` was not enabled). As
an alternative, the latest Ubuntu server image was installed and functioned as
expected.

One unsurprising caveat of usage on the Pi 4 is that an eBPF program can
only be attached to an interface in generic mode. Additionally, it does not
support jumbo frames -- so all testing was with a 1500-byte MTU.

