use libc;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{convert::TryInto, io, ptr};
use std::ffi::CString;
use std::os::raw::c_int;
use std::result::Result;
use std::str::FromStr;

use crate::wol::{ WolErr, WolErrCode };

const ANY_PORT : u16 = 0;
const ANY_INTERFACE: &str = "ANY_INTERFACE";
const IPV4_ANY_ADDR : &str = "0.0.0.0";
const IPV6_ANY_ADDR : &str = "::";

type CSocket = c_int;

pub trait WolSocket {
    fn send_magic_packet(&self, buf : &[u8], addr: &str) -> Result<usize, WolErr>;

    fn get_socket(&self) -> CSocket;

    //fn bind_to_intf(&self, intf: &str) -> Result<(), WolErr>;
}

pub struct RawSocket{
    pub cs: CSocket
}

impl RawSocket {
    pub fn new(intf_name: &str) -> Result<RawSocket, WolErr> {
        println!("Creating raw socket");
        let addr_ll: libc::sockaddr_ll = RawSocket::generate_sockaddr_ll(intf_name)?;
        let res = unsafe {
            libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be())
        };
        if res < 0 {
            return Err(WolErr {
                msg: format!("Failed to create raw socket: {}", io::Error::last_os_error().to_string()),
                code: WolErrCode::SocketError as i32
            })
        } 
        if unsafe {
            libc::bind(
                res,
                &addr_ll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        } != 0 {
            return Err(WolErr {
                msg: io::Error::last_os_error().to_string(),
                code: WolErrCode::SocketError as i32,
            })
        }

        Ok(RawSocket{ cs: res })
    }

    fn generate_sockaddr_ll(intf_name: &str) -> Result<libc::sockaddr_ll, WolErr> {
        println!("Generating sockaddr_ll for interface {}", intf_name);
        let mut addr_ll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr_ll.sll_family = libc::AF_PACKET as u16;
        addr_ll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr_ll.sll_halen = 6; // MAC address length in bytes

        let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
        println!("Getting interface addresses");
        if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
            return Err(WolErr {
                msg: format!("getifaddrs got error: {}", io::Error::last_os_error().to_string()),
                code: WolErrCode::SocketError as i32,
            });
        }

        let mut addr = addrs;
        while !addr.is_null() {
            println!("Iterating over interface addresses");
            let addr_ref = unsafe { *addr };
            if addr_ref.ifa_name.is_null() {
                println!("skip one interface that ifa_name is null");
                addr = addr_ref.ifa_next;
                continue;
            }

            let _in = unsafe { std::ffi::CStr::from_ptr(addr_ref.ifa_name).to_str().unwrap() };
            println!("Current interface name: {}", _in);
            if _in == intf_name {
                addr_ll.sll_ifindex = unsafe {
                    libc::if_nametoindex(addr_ref.ifa_name) as i32
                };
                addr_ll.sll_addr = unsafe { (*(addr_ref.ifa_addr as *const libc::sockaddr_ll)).sll_addr };
                break;
            }
            
            addr = addr_ref.ifa_next;
        }

        println!("free interfaces information linked list");
        unsafe {
            libc::freeifaddrs(addrs);
        }

        Ok(addr_ll)
    }
}

impl WolSocket for RawSocket {
    fn get_socket(&self) -> CSocket { self.cs }

    fn send_magic_packet(&self, buf : &[u8], _: &str) -> Result<usize, WolErr> {
        let res = unsafe {
            libc::send(self.get_socket(), buf.as_ptr() as *const libc::c_void, buf.len(), 0)
        };
        if res < 0 {
            Err(WolErr { msg: io::Error::last_os_error().to_string(), code: WolErrCode::SocketError as i32 })
        } else {
            Ok(res as usize)
        }
    }
}

#[derive(Debug)]
pub struct UdpSocket{
    pub cs: CSocket
}

impl UdpSocket {
    pub fn new(intf_name: &str, dst_port: u16, ip_addr: &str) -> Result<UdpSocket, WolErr> {
        let res = match ip_addr.contains(":") {
            true => unsafe {libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP)},
            false => unsafe {libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP)},
        };
        if res < 0 {
            return Err(WolErr {
                msg: format!("Failed to create udp socket: {}", io::Error::last_os_error().to_string()),
                code: WolErrCode::SocketError as i32
            })
        }
        let _socket = UdpSocket{ cs: res };
        _socket.enable_broadcast()?;
        _socket.bind_to_addr(ip_addr, intf_name)?;
        _socket.bind_to_intf(intf_name)?;
        _socket.connect_to_addr(dst_port, ip_addr)?;
        Ok(_socket)
    }

    fn enable_broadcast(&self) -> Result<(), WolErr> {
        let res = unsafe {
            libc::setsockopt(
                self.get_socket(),
                libc::SOL_SOCKET,
                libc::SO_BROADCAST,
                &1 as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>().try_into().unwrap(),
            )
        };
        if res == -1 {
            Err(WolErr {
                msg: format!("Failed to enable broadcast on udp socket: {}", io::Error::last_os_error().to_string()),
                code: WolErrCode::SocketError as i32,
            })
        } else {
            Ok(())
        }
    }

    fn bind_to_intf(&self, intf: &str) -> Result<(), WolErr> {
        let c_intf = CString::new(intf).map_err(|_| WolErr {
            msg: String::from("Invalid interface name for binding"),
            code: WolErrCode::SocketError as i32,
        })?;
        let res = unsafe {
            libc::setsockopt(
                self.get_socket(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                c_intf.as_ptr() as *const libc::c_void,
                c_intf.as_bytes_with_nul().len() as u32,
            )
        };
        if res == -1 {
            Err(WolErr {
                msg: format!("Failed to bind udp socket to interface: {}", io::Error::last_os_error().to_string()),
                code: WolErrCode::SocketError as i32,
            })
        } else {
            Ok(())
        }
    }

    fn bind_to_addr(&self, ip_addr: &str, intf_name: &str) -> Result<(), WolErr> {
        let addr = match ip_addr.contains(":") {
            true => &ipv6_addr(9, IPV6_ANY_ADDR, intf_name)? as *const libc::sockaddr_in6 as *const libc::sockaddr,
            false => &ipv4_addr(ANY_PORT, IPV4_ANY_ADDR)? as *const libc::sockaddr_in as *const libc::sockaddr,
        };
        let res = unsafe {
            libc::bind(
                self.get_socket(),
                addr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if res != 0 {
            Err(WolErr {
                msg: format!("Failed to bind udp socket to address: {} with rc: {}", io::Error::last_os_error().to_string(), res),
                code: WolErrCode::SocketError as i32,
            })
        } else {
            Ok(())
        }
    }

    fn connect_to_addr(&self, port: u16, ip_addr: &str) -> Result<(), WolErr> {
        println!("Connecting to dst address: {} and dst port: {}", ip_addr, port);
        let (addr, addr_len) = match ip_addr.contains(":") {
            true => (
                &ipv6_addr(port, ip_addr, ANY_INTERFACE)? as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as u32
            ),
            false => (
                &ipv4_addr(port, ip_addr)? as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32
            ),
        };
        let res = unsafe {
            libc::connect(
                self.get_socket(),
                addr,
                addr_len
            )
        };
        if res != 0 {
            Err(WolErr {
                msg: format!("Failed to connect udp socket to address: {} and port: {} with rc: {}", io::Error::last_os_error().to_string(), port, res),
                code: WolErrCode::SocketError as i32,
            })
        } else {
            Ok(())
        }
    }
}

impl WolSocket for UdpSocket {
    fn get_socket(&self) -> CSocket { self.cs }

    fn send_magic_packet(&self, buf : &[u8], _: &str) -> Result<usize, WolErr> {
        let res = unsafe {
            libc::send(self.get_socket(), buf.as_ptr() as *const libc::c_void, buf.len(), 0)
        };
        if res < 0 {
            Err(WolErr { msg: io::Error::last_os_error().to_string(), code: WolErrCode::SocketError as i32 })
        } else {
            Ok(res as usize)
        }
    }
}

fn ipv4_addr(port: u16, addr: &str) -> Result<libc::sockaddr_in, WolErr> {
    let _addr = match addr == IPV4_ANY_ADDR {
        true => libc::in_addr { s_addr: libc::INADDR_ANY },
        false => libc::in_addr { s_addr: u32::from(Ipv4Addr::from_str(addr).map_err(|e| 
                WolErr{
                    msg: format!("Failed to parse ipv4 address: {}", e),
                    code: WolErrCode::SocketError as i32
                }
            )?).to_be()
        },
    };
    Ok(
        libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: port,
            sin_addr: _addr,
            sin_zero: [0; 8],
        }
    )
}

fn ipv6_addr(port: u16, addr: &str, intf_name: &str) -> Result<libc::sockaddr_in6, WolErr> {
    let _addr = match addr == IPV6_ANY_ADDR {
        true => libc::IN6ADDR_ANY_INIT,
        false => libc::in6_addr { s6_addr: Ipv6Addr::from_str(addr).map_err(|e| 
                WolErr{
                    msg: format!("Failed to parse ipv6 address: {}", e),
                    code: WolErrCode::SocketError as i32
                }
            )?.octets()
        },
    };
    let _scope_id= match intf_name == ANY_INTERFACE {
        true => 0,
        false => unsafe { libc::if_nametoindex(CString::new(intf_name).map_err(|_| 
                WolErr{
                    msg: String::from("Invalid interface name for binding"),
                    code: WolErrCode::SocketError as i32
                }
            )?.as_ptr()) as u32
        }
    };
    println!("ipv6_addr: {} and port {} with scope_id: {}", _addr.s6_addr
    .iter()
    .fold(String::new(), |acc, b| acc + &format!("{:02X}", b)), port, _scope_id);
    Ok(
        libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as u16,
            sin6_port: port,
            sin6_flowinfo: 0,
            sin6_addr: _addr,
            sin6_scope_id: _scope_id,
        }
    )
}