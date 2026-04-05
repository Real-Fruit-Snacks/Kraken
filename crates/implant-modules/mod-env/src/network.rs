//! Network information gathering — interfaces, DNS servers, default gateway

use common::{KrakenError, NetworkInfoOutput, NetworkInterfaceInfo};

pub fn get_network_info() -> Result<NetworkInfoOutput, KrakenError> {
    get_network_info_impl()
}

// ============================================================
// Windows implementation
// ============================================================

#[cfg(windows)]
fn get_network_info_impl() -> Result<NetworkInfoOutput, KrakenError> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;

    const AF_UNSPEC: u32 = 0;

    let mut buf_len: u32 = 15000;
    let mut buf: Vec<u8> = vec![0u8; buf_len as usize];

    // May need to retry with larger buffer
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };

    let buf = if ret == ERROR_BUFFER_OVERFLOW {
        let mut buf2 = vec![0u8; buf_len as usize];
        let ret2 = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX,
                std::ptr::null_mut(),
                buf2.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
        if ret2 != 0 {
            return Ok(NetworkInfoOutput {
                interfaces: vec![],
                dns_servers: vec![],
                default_gateway: String::new(),
            });
        }
        buf2
    } else if ret != 0 {
        return Ok(NetworkInfoOutput {
            interfaces: vec![],
            dns_servers: vec![],
            default_gateway: String::new(),
        });
    } else {
        buf
    };

    let mut interfaces = Vec::new();
    let mut dns_servers = Vec::new();
    let mut default_gateway = String::new();

    let mut adapter_ptr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    while !adapter_ptr.is_null() {
        let adapter = unsafe { &*adapter_ptr };

        // Adapter name (friendly name is wide string)
        let name = if !adapter.FriendlyName.is_null() {
            let mut len = 0usize;
            let ptr = adapter.FriendlyName;
            while unsafe { *ptr.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
            String::from_utf16_lossy(slice)
        } else {
            String::new()
        };

        // MAC address
        let mac_len = adapter.PhysicalAddressLength as usize;
        let mac_address = if mac_len > 0 {
            adapter.PhysicalAddress[..mac_len]
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        } else {
            String::new()
        };

        // Is up? OperStatus == 1 means IfOperStatusUp
        let is_up = adapter.OperStatus == 1;

        // Unicast addresses
        let mut ipv4_addresses = Vec::new();
        let mut ipv6_addresses = Vec::new();

        let mut ua_ptr = adapter.FirstUnicastAddress;
        while !ua_ptr.is_null() {
            let ua = unsafe { &*ua_ptr };
            let sa = ua.Address.lpSockaddr;
            if !sa.is_null() {
                let family = unsafe { (*sa).sa_family };
                if family == 2 {
                    // AF_INET
                    let sa4 = sa as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
                    let addr = unsafe { (*sa4).sin_addr.S_un.S_addr };
                    let ip = Ipv4Addr::from(u32::from_be(addr));
                    ipv4_addresses.push(ip.to_string());
                } else if family == 23 {
                    // AF_INET6
                    let sa6 = sa as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6;
                    let bytes = unsafe { (*sa6).sin6_addr.u.Byte };
                    let ip = Ipv6Addr::from(bytes);
                    ipv6_addresses.push(ip.to_string());
                }
            }
            ua_ptr = ua.Next;
        }

        // DNS servers
        let mut dns_ptr = adapter.FirstDnsServerAddress;
        while !dns_ptr.is_null() {
            let dns = unsafe { &*dns_ptr };
            let sa = dns.Address.lpSockaddr;
            if !sa.is_null() {
                let family = unsafe { (*sa).sa_family };
                if family == 2 {
                    let sa4 = sa as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
                    let addr = unsafe { (*sa4).sin_addr.S_un.S_addr };
                    let ip = Ipv4Addr::from(u32::from_be(addr));
                    let s = ip.to_string();
                    if !dns_servers.contains(&s) {
                        dns_servers.push(s);
                    }
                }
            }
            dns_ptr = dns.Next;
        }

        // Default gateway
        let mut gw_ptr = adapter.FirstGatewayAddress;
        if !gw_ptr.is_null() && default_gateway.is_empty() {
            let gw = unsafe { &*gw_ptr };
            let sa = gw.Address.lpSockaddr;
            if !sa.is_null() {
                let family = unsafe { (*sa).sa_family };
                if family == 2 {
                    let sa4 = sa as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
                    let addr = unsafe { (*sa4).sin_addr.S_un.S_addr };
                    let ip = Ipv4Addr::from(u32::from_be(addr));
                    default_gateway = ip.to_string();
                }
            }
        }

        interfaces.push(NetworkInterfaceInfo {
            name,
            mac_address,
            ipv4_addresses,
            ipv6_addresses,
            is_up,
        });

        adapter_ptr = adapter.Next;
    }

    Ok(NetworkInfoOutput {
        interfaces,
        dns_servers,
        default_gateway,
    })
}

// ============================================================
// Linux / Unix implementation
// ============================================================

#[cfg(unix)]
fn get_network_info_impl() -> Result<NetworkInfoOutput, KrakenError> {
    let interfaces = enumerate_interfaces()?;
    let dns_servers = read_dns_servers();
    let default_gateway = read_default_gateway();

    Ok(NetworkInfoOutput {
        interfaces,
        dns_servers,
        default_gateway,
    })
}

#[cfg(unix)]
fn enumerate_interfaces() -> Result<Vec<NetworkInterfaceInfo>, KrakenError> {
    let mut result = Vec::new();

    // Use getifaddrs
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Ok(result);
    }

    // Collect all addresses grouped by interface name
    let mut iface_map: std::collections::HashMap<String, NetworkInterfaceInfo> =
        std::collections::HashMap::new();

    let mut ifa = ifap;
    while !ifa.is_null() {
        let iface = unsafe { &*ifa };
        let name = unsafe { std::ffi::CStr::from_ptr(iface.ifa_name) }
            .to_string_lossy()
            .into_owned();

        let is_up = (iface.ifa_flags as i32 & libc::IFF_UP) != 0;

        let entry = iface_map.entry(name.clone()).or_insert_with(|| NetworkInterfaceInfo {
            name: name.clone(),
            mac_address: String::new(),
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            is_up,
        });

        // Update is_up (may be set on any of the entries)
        entry.is_up = is_up;

        if !iface.ifa_addr.is_null() {
            let family = unsafe { (*iface.ifa_addr).sa_family as i32 };

            if family == libc::AF_INET {
                let sa = iface.ifa_addr as *const libc::sockaddr_in;
                let addr = unsafe { (*sa).sin_addr.s_addr };
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr));
                entry.ipv4_addresses.push(ip.to_string());
            } else if family == libc::AF_INET6 {
                let sa6 = iface.ifa_addr as *const libc::sockaddr_in6;
                let bytes = unsafe { (*sa6).sin6_addr.s6_addr };
                let ip = std::net::Ipv6Addr::from(bytes);
                entry.ipv6_addresses.push(ip.to_string());
            } else if family == libc::AF_PACKET {
                // Hardware address (MAC) on Linux
                #[cfg(target_os = "linux")]
                {
                    let sll = iface.ifa_addr as *const libc::sockaddr_ll;
                    let halen = unsafe { (*sll).sll_halen as usize };
                    if halen == 6 {
                        let mac = &unsafe { (*sll).sll_addr }[..6];
                        entry.mac_address = mac
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(":");
                    }
                }
            }
        }

        ifa = iface.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifap) };

    result.extend(iface_map.into_values());
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

#[cfg(unix)]
fn read_dns_servers() -> Vec<String> {
    let mut servers = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("nameserver ") {
                let s = val.trim().to_string();
                if !s.is_empty() && !servers.contains(&s) {
                    servers.push(s);
                }
            }
        }
    }
    servers
}

#[cfg(unix)]
fn read_default_gateway() -> String {
    // Parse /proc/net/route for default gateway (destination = 00000000)
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "00000000" {
                // Gateway in little-endian hex
                if let Ok(gw_hex) = u32::from_str_radix(fields[2], 16) {
                    let ip = std::net::Ipv4Addr::from(u32::from_le(gw_hex));
                    return ip.to_string();
                }
            }
        }
    }
    String::new()
}
