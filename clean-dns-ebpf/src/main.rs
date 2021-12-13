#![no_std]
#![no_main]
#![feature(label_break_value)]

#[allow(dead_code, non_camel_case_types, unused)]
mod bindings;
#[allow(dead_code, non_camel_case_types, unused)]
mod constants;

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use bindings::{ethhdr, iphdr, udphdr};
use clean_dns_common::PacketLog;
use constants::{ETH_HLEN, ETH_P_IP, IPPROTO_UDP};
use core::mem;
use memoffset::offset_of;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp(name = "clean_dns")]
pub fn clean_dns(ctx: XdpContext) -> u32 {
    match try_clean_dns(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_clean_dns(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    // only match ip
    if h_proto != ETH_P_IP as u16 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip: *const iphdr = unsafe { ptr_at(&ctx, ETH_HLEN as usize)? };
    let protocol = unsafe { (*ip).protocol };
    let source = u32::from_be(unsafe { (*ip).saddr });
    let destination = u32::from_be(unsafe { (*ip).daddr });

    let mut log_entry = PacketLog {
        ipv4_src_addr: source,
        ipv4_dst_addr: destination,
        action: xdp_action::XDP_PASS,
    };
    // only match udp and BLOCKLIST
    if protocol != IPPROTO_UDP as u8 || !block_ip(source) {
        return Ok(xdp_action::XDP_PASS);
    }

    let udphdr: *const udphdr =
        unsafe { ptr_at(&ctx, ETH_HLEN as usize + ((*ip).ihl() * 4) as usize)? };
    let source = u16::from_be(unsafe { (*udphdr).source });
    // only match 53
    if source != 53 {
        return Ok(xdp_action::XDP_PASS);
    }
    let action = 'check: {
        // drop if id is 0
        if u16::from_be(unsafe { (*ip).id }) == 0 {
            break 'check xdp_action::XDP_DROP;
        }
        // drop if flag is 0x40(Don't fragment)
        if u16::from_be(unsafe { (*ip).frag_off }) == 0x0040 {
            break 'check xdp_action::XDP_DROP;
        }
        // get first 10 byte udp data(7,8 is Answer RRs, 8,9 is Authority RRs)
        let data: [u8; 10] = unsafe {
            *ptr_at(
                &ctx,
                ETH_HLEN as usize + ((*ip).ihl() * 4) as usize + core::mem::size_of::<udphdr>(),
            )?
        };
        // pass if the dns packet has multiple answers
        if data[6] != 0 || data[7] != 1 {
            // Answer RR != 1
            break 'check xdp_action::XDP_PASS;
        }
        // pass if the dns packet has authority answer
        if data[8] != 0 || data[9] != 0 {
            // Authority RR != 0
            break 'check xdp_action::XDP_PASS;
        }
        // drop if dns flag has Authoritative mark
        if (data[2] & 0b0000_0100) != 0 {
            break 'check xdp_action::XDP_DROP;
        }
        xdp_action::XDP_PASS
    };
    log_entry.action = action;
    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    return Ok(action);
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

#[inline(always)]
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}
