// Minimal reproduction: a dropped TcpListener can still accept connections
// while another thread is inside Command::spawn, because the child's copy of
// the fd table keeps the listening socket alive until execve closes it.
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let spawners: usize = std::env::args().nth(1).map_or(4, |s| s.parse().unwrap());
    let iterations: usize = std::env::args().nth(2).map_or(20_000, |s| s.parse().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for _ in 0..spawners {
        let stop = stop.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = Command::new("/bin/true").status();
            }
        }));
    }
    let (mut connected, mut reset) = (0, 0);
    for _ in 0..iterations {
        let port = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        }; // probe dropped here: nothing in this process listens on `port` any more
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            connected += 1;
            s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut b = [0u8; 1];
            if let Err(e) = s.read(&mut b) {
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    reset += 1;
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }
    println!(
        "spawner_threads={spawners} probes={iterations} connected_to_dropped_listener={connected} then_reset={reset}"
    );
}
