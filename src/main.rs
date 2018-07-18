extern crate base64;
extern crate futures;
extern crate libc;
#[macro_use]
extern crate nix;
extern crate tk_listen;
extern crate tokio;
extern crate tokio_current_thread;

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::{self, ErrorKind};
use std::net::{Shutdown, SocketAddr};
use std::process;
use std::process::Command;
use std::process::Stdio;
use std::str;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use tk_listen::ListenExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use std::sync::Arc;

fn main() {
    let listen_addr = "127.0.0.1:534".to_string().parse().unwrap();
    let proxy_addr = env::var("PROXY")
        .unwrap_or("10.142.90.220:80".to_string())
        .parse()
        .expect("Not a valid proxy address");
    let username = env::var("PROXY_USER").expect("No username specified");
    let password = env::var("PROXY_PASSWORD").expect("No password specified");

    println!("Connecting to {} as user {}", proxy_addr, username);

    let authorization = username.to_string() + ":" + &password;
    let proxy_authorization = base64::encode(&authorization);
    let firewall = Pf::new();

    let context = Context {
        proxy_authorization,
        proxy_addr,
        firewall,
    };

    ctrlc::set_handler(|| {
        Proxy::disable();
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let proxy = Arc::new(Mutex::new(Proxy::new(proxy_addr)));
    proxy.lock().unwrap().watch();

    let server = TcpListener::bind(&listen_addr)
        .expect("Could not bind to port")
        .incoming()
        .sleep_on_error(Duration::from_millis(100))
        .map(move |client| {
            let proxy = proxy.clone();
            connect(&context, client).map_err(move |e| {
                match e {
                    AppError::Io(e) => {
                        println!("Connection error: {:?}", e);
                        proxy.lock().unwrap().watch();
                    }
                    AppError::ProxyError(_) => {
                        // Ignore
                    }
                }
                // Do not propagate errors
                return ();
            })
        })
        .listen(1000);

    // Use the current_thread executor which uses a single thread for everything. Our proxy is
    // completely IO bound and having only a single thread means we don't perform any expensive
    // context switching.
    tokio_current_thread::block_on_all(server).unwrap();
}

fn connect(context: &Context, client: TcpStream) -> impl Future<Item = (), Error = AppError> {
    // Get the original destination from the firewall routing table
    let target = context.firewall.lookup(&client).expect("No result");

    // println!("{:>5} -> {}", client.peer_addr().unwrap().port(), target);

    let connect = format!(
        "CONNECT {}:{} HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
        target.ip(),
        target.port(),
        context.proxy_authorization
    );

    TcpStream::connect(&context.proxy_addr)
        .and_then(|proxy| tokio::io::write_all(proxy, connect))
        .and_then(|(proxy, _)| {
            // Read the server response
            let response = vec![];
            let proxy = BufReader::new(proxy);
            tokio::io::read_until(proxy, b'\r', response).and_then(|(proxy, response)| {
                // Read remaining newlines '\n\r\n'
                tokio::io::read_exact(proxy, vec![3]).and_then(move |(proxy, _)| {
                    // Remove BufReader
                    Ok((proxy.into_inner(), response))
                })
            })
        })
        .map_err(AppError::from)
        .and_then(move |(proxy, response)| {
            // Check if there is a 200 response code
            if !response.starts_with(b"HTTP/1.1 200") {
                let header = str::from_utf8(&response).unwrap();
                println!("Error to {}: {}", target, header);
                return Err(AppError::ProxyError(header.into()));
            }
            Ok(proxy)
        })
        .then(|res| {
            // Close client connection on proxy error
            match res {
                Ok(proxy) => Ok((proxy, client)),
                Err(e) => {
                    // Ignore errors, client might have already shutdown
                    client.shutdown(Shutdown::Both);
                    Err(e)
                }
            }
        })
        .and_then(|(proxy, client)| {
            let (client_read, client_write) = client.split();
            let (proxy_read, proxy_write) = proxy.split();
            // Spawn two independent copy actions since a connection can be half
            // open (joining will stop both futures on the first error).
            tokio_current_thread::spawn(
                tokio::io::copy(client_read, proxy_write)
                    .map(move |(_, _, mut writer)| writer.shutdown())
                    .then(end_connection),
            );
            tokio_current_thread::spawn(
                tokio::io::copy(proxy_read, client_write)
                    .map(move |(_, _, mut writer)| writer.shutdown())
                    .then(end_connection),
            );
            Ok(())
        })
}

fn end_connection<T>(result: Result<T, io::Error>) -> Result<(), ()> {
    if let Err(e) = result {
        match e.kind() {
            ErrorKind::NotConnected | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
                return Ok(());
            }
            _ => println!("connection: {:?}", e),
        }
    }
    Ok(())
}
struct Context {
    proxy_addr: SocketAddr,
    proxy_authorization: String,
    firewall: Pf,
}

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    ProxyError(String),
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> AppError {
        AppError::Io(err)
    }
}

struct Pf {
    file: File,
}

impl Pf {
    pub fn new() -> Pf {
        let file = File::open("/dev/pf").expect("Could not open /dev/pf");
        Pf { file }
    }

    pub fn lookup(&self, socket: &TcpStream) -> Result<SocketAddr, nix::Error> {
        ioctl::lookup(&self.file, socket)
    }
}

struct Proxy {
    // TODO: Make this better
    watching: Arc<Mutex<bool>>,
    addr: SocketAddr,
}

impl Proxy {
    pub fn new(addr: SocketAddr) -> Proxy {
        Proxy {
            watching: Arc::new(Mutex::new(false)),
            addr,
        }
    }

    fn watch(&mut self) {
        let mut watching = self.watching.lock().expect("Could not lock");
        if *watching {
            return;
        }

        Proxy::disable();

        *watching = true;

        let watching = self.watching.clone();
        let addr = self.addr.clone();

        thread::spawn(move || 'task: loop {
            match std::net::TcpStream::connect(addr) {
                Ok(conn) => {
                    conn.shutdown(Shutdown::Both)
                        .expect("Could not close connection");
                    let mut watching = watching.lock().expect("Could not lock");
                    Proxy::enable();
                    *watching = false;
                    break 'task;
                }
                Err(_e) => {}
            }
            thread::sleep(Duration::from_millis(3000));
        });
    }

    fn disable() {
        println!("Reset proxy");
        Command::new("pfctl")
            .arg("-e")
            .stderr(Stdio::null())
            .status()
            .expect("Could not enable firewall");

        Command::new("pfctl")
            .args(&["-a", "proxy", "-F", "all"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
            .wait()
            .expect("Could not disable firewall rules");
    }

    fn enable() {
        println!("Enabling proxy");
        let mut process = Command::new("pfctl")
            .args(&["-a", "proxy", "-F", "all", "-f", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        process
            .stdin
            .as_mut()
            .unwrap()
            .write_all(include_bytes!("pf.conf"))
            .expect("Could not write to pf");

        process.wait().expect("Could not update firewall rules");
    }
}

mod ioctl {
    use libc;
    use nix::Error;
    use std::fs::File;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;

    const PF_OUT: u8 = 2;

    #[repr(C)]
    pub union pf_addr {
        v4addr: [u8; 4],
        v6addr: [u8; 16],
    }

    impl pf_addr {
        fn from(addr: IpAddr) -> pf_addr {
            match addr {
                IpAddr::V4(addr) => pf_addr {
                    v4addr: addr.octets(),
                },
                IpAddr::V6(addr) => pf_addr {
                    v6addr: addr.octets(),
                },
            }
        }

        fn unspecified() -> pf_addr {
            pf_addr {
                v4addr: [0, 0, 0, 0],
            }
        }
    }

    #[repr(C)]
    pub union pf_state_xport {
        port: u16,
        call_id: u16,
        spi: u32,
    }

    impl pf_state_xport {
        fn new(port: u16) -> pf_state_xport {
            pf_state_xport { port: port.to_be() }
        }
    }

    #[repr(C)]
    pub struct pfioc_natlook {
        saddr: pf_addr,
        daddr: pf_addr,
        rsaddr: pf_addr,
        rdaddr: pf_addr,
        sxport: pf_state_xport,
        dxport: pf_state_xport,
        rsxport: pf_state_xport,
        rdxport: pf_state_xport,
        af: libc::sa_family_t,
        proto: u8,
        proto_variant: u8,
        direction: u8,
    }

    ioctl_readwrite!(diocnatlook, b'D', 23, pfioc_natlook);

    pub fn lookup(file: &File, socket: &TcpStream) -> Result<SocketAddr, Error> {
        let peer_addr = socket
            .peer_addr()
            .expect("Could not get peer address from connection");
        let local_addr = socket
            .local_addr()
            .expect("Could not get local address from connection");
        let mut data = pfioc_natlook {
            saddr: pf_addr::from(peer_addr.ip()),
            daddr: pf_addr::from(local_addr.ip()),
            rsaddr: pf_addr::unspecified(),
            rdaddr: pf_addr::unspecified(),
            sxport: pf_state_xport::new(peer_addr.port()),
            dxport: pf_state_xport::new(local_addr.port()),
            rsxport: pf_state_xport::new(0),
            rdxport: pf_state_xport::new(0),
            af: libc::AF_INET as u8,
            proto: libc::IPPROTO_TCP as u8,
            proto_variant: 0,
            direction: PF_OUT,
        };
        let fd = file.as_raw_fd();
        unsafe {
            diocnatlook(fd, &mut data)?;
        };
        let ip = IpAddr::V4(Ipv4Addr::from(unsafe { data.rdaddr.v4addr }));
        let port = u16::from_be(unsafe { data.rdxport.port });
        Ok(SocketAddr::new(ip, port))
    }
}
