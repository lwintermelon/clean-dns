use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clean_dns_common::PacketLog;
use std::{
    convert::{TryFrom, TryInto},
    net::{self, Ipv4Addr},
};
use structopt::StructOpt;
use tokio::{self, signal, task};

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/clean-dns"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/clean-dns"
    ))?;
    let program: &mut Xdp = bpf.program_mut("clean_dns").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;
    blocklist.insert(Ipv4Addr::new(8, 8, 8, 8).try_into()?, 0, 0)?;
    blocklist.insert(Ipv4Addr::new(1, 1, 1, 1).try_into()?, 0, 0)?;

    println!("Waiting for Ctrl-C...");
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.ipv4_src_addr);
                    let dst_addr = net::Ipv4Addr::from(data.ipv4_dst_addr);
                    println!(
                        "LOG: SRC {}, DST {}, ACTION {}",
                        src_addr, dst_addr, data.action
                    );
                }
            }
        });
    }
    signal::ctrl_c().await.expect("failed to listen for event");
    println!("Exiting...");

    Ok(())
}
