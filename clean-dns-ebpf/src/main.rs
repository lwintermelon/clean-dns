#![no_std]
#![no_main]
mod bindings;
use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use bindings::{ethhdr, iphdr, ETH_HLEN, ETH_P_IP};
use clean_dns_common::PacketLog;
use core::mem;
use memoffset::offset_of;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[xdp(name = "clean_dns")]
pub fn clean_dns(ctx: XdpContext) -> u32 {
    match try_clean_dns(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_clean_dns(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IP as u16 {
        return Ok(xdp_action::XDP_PASS);
    }
    let source =
        u32::from_be(unsafe { *ptr_at(&ctx, ETH_HLEN as usize + offset_of!(iphdr, saddr))? });
    let destination =
        u32::from_be(unsafe { *ptr_at(&ctx, ETH_HLEN as usize + offset_of!(iphdr, daddr))? });
    let log_entry = PacketLog {
        ipv4_src_addr: source,
        ipv4_dst_addr: destination,
        action: xdp_action::XDP_PASS,
    };
    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
