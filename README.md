

# photonos-netmgr

## Overview
Network Configuration Manager library is developed with the goal of providing a set of APIs for common tasks such as configuring IP addresses, network routes, interface states, DNS, etc. This allows the user to configure the network on a Photon OS through simpler API calls that handle much of the complexity of configuring the network, which the user would have to do if they took the route of directly manipulating the various configuration files.
## Try it out

### Prerequisites

* systemd, ntp, pcre, iputils
* docker, check, glib-devel, autoconf

### Build & Run

1. autoreconf -mif
2. ./configure
3. make

## Documentation
1. The goals of this project are:
* Provide a programmatic interface that allows configuring the following settings on Photon OS:
* IPv4 and IPv6 addresses
* Interface states for devices and virtual interfaces (stretch)
* Routes
* DNS server and domain settings
* DHCP DUID and IAID configuration
* NTP server configuration
* Atomic update of configuration files.

2. API set should enable configuration of common network settings with minimal effort
* Provide Python interface for easy integration in appliance shell python codebase
* Provide REST API interface (through [Photon Management Daemon](https://github.com/vmware/pmd))
## Releases & Major Branches

## Contributing

The photonos-netmgr project team welcomes contributions from the community. If you wish to contribute code and you have not
signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any
questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq). For more detailed information,
refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
