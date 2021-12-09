/* automatically generated by rust-bindgen 0.59.2 */
#![allow(dead_code, non_camel_case_types, unused)]

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}
impl<Storage> __BindgenBitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}
impl<Storage> __BindgenBitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}
pub type __u8 = ::aya_bpf::cty::c_uchar;
pub type __u16 = ::aya_bpf::cty::c_ushort;
pub type __u32 = ::aya_bpf::cty::c_uint;
pub type __be16 = __u16;
pub type __be32 = __u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ethhdr {
    pub h_dest: [::aya_bpf::cty::c_uchar; 6usize],
    pub h_source: [::aya_bpf::cty::c_uchar; 6usize],
    pub h_proto: __be16,
}
pub type __sum16 = __u16;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iphdr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
    pub tos: __u8,
    pub tot_len: __be16,
    pub id: __be16,
    pub frag_off: __be16,
    pub ttl: __u8,
    pub protocol: __u8,
    pub check: __sum16,
    pub saddr: __be32,
    pub daddr: __be32,
}
impl iphdr {
    #[inline]
    pub fn ihl(&self) -> __u8 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_ihl(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn version(&self) -> __u8 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_version(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::core::mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(ihl: __u8, version: __u8) -> __BindgenBitfieldUnit<[u8; 1usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 4u8, {
            let ihl: u8 = unsafe { ::core::mem::transmute(ihl) };
            ihl as u64
        });
        __bindgen_bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { ::core::mem::transmute(version) };
            version as u64
        });
        __bindgen_bitfield_unit
    }
}

impl<Storage> __BindgenBitfieldUnit<Storage> {}
impl ethhdr {
    pub fn h_dest(&self) -> Option<[::aya_bpf::cty::c_uchar; 6usize]> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.h_dest) }.ok()
    }
    pub fn h_source(&self) -> Option<[::aya_bpf::cty::c_uchar; 6usize]> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.h_source) }.ok()
    }
    pub fn h_proto(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.h_proto) }.ok()
    }
}
impl iphdr {
    pub fn tos(&self) -> Option<__u8> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.tos) }.ok()
    }
    pub fn tot_len(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.tot_len) }.ok()
    }
    pub fn id(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.id) }.ok()
    }
    pub fn frag_off(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.frag_off) }.ok()
    }
    pub fn ttl(&self) -> Option<__u8> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.ttl) }.ok()
    }
    pub fn protocol(&self) -> Option<__u8> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.protocol) }.ok()
    }
    pub fn check(&self) -> Option<__sum16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.check) }.ok()
    }
    pub fn saddr(&self) -> Option<__be32> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.saddr) }.ok()
    }
    pub fn daddr(&self) -> Option<__be32> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.daddr) }.ok()
    }
}

pub const ETH_ALEN: u32 = 6;
pub const ETH_TLEN: u32 = 2;
pub const ETH_HLEN: u32 = 14;
pub const ETH_ZLEN: u32 = 60;
pub const ETH_DATA_LEN: u32 = 1500;
pub const ETH_FRAME_LEN: u32 = 1514;
pub const ETH_FCS_LEN: u32 = 4;
pub const ETH_MIN_MTU: u32 = 68;
pub const ETH_MAX_MTU: u32 = 65535;
pub const ETH_P_LOOP: u32 = 96;
pub const ETH_P_PUP: u32 = 512;
pub const ETH_P_PUPAT: u32 = 513;
pub const ETH_P_TSN: u32 = 8944;
pub const ETH_P_ERSPAN2: u32 = 8939;
pub const ETH_P_IP: u32 = 2048;
pub const ETH_P_X25: u32 = 2053;
pub const ETH_P_ARP: u32 = 2054;
pub const ETH_P_BPQ: u32 = 2303;
pub const ETH_P_IEEEPUP: u32 = 2560;
pub const ETH_P_IEEEPUPAT: u32 = 2561;
pub const ETH_P_BATMAN: u32 = 17157;
pub const ETH_P_DEC: u32 = 24576;
pub const ETH_P_DNA_DL: u32 = 24577;
pub const ETH_P_DNA_RC: u32 = 24578;
pub const ETH_P_DNA_RT: u32 = 24579;
pub const ETH_P_LAT: u32 = 24580;
pub const ETH_P_DIAG: u32 = 24581;
pub const ETH_P_CUST: u32 = 24582;
pub const ETH_P_SCA: u32 = 24583;
pub const ETH_P_TEB: u32 = 25944;
pub const ETH_P_RARP: u32 = 32821;
pub const ETH_P_ATALK: u32 = 32923;
pub const ETH_P_AARP: u32 = 33011;
pub const ETH_P_8021Q: u32 = 33024;
pub const ETH_P_ERSPAN: u32 = 35006;
pub const ETH_P_IPX: u32 = 33079;
pub const ETH_P_IPV6: u32 = 34525;
pub const ETH_P_PAUSE: u32 = 34824;
pub const ETH_P_SLOW: u32 = 34825;
pub const ETH_P_WCCP: u32 = 34878;
pub const ETH_P_MPLS_UC: u32 = 34887;
pub const ETH_P_MPLS_MC: u32 = 34888;
pub const ETH_P_ATMMPOA: u32 = 34892;
pub const ETH_P_PPP_DISC: u32 = 34915;
pub const ETH_P_PPP_SES: u32 = 34916;
pub const ETH_P_LINK_CTL: u32 = 34924;
pub const ETH_P_ATMFATE: u32 = 34948;
pub const ETH_P_PAE: u32 = 34958;
pub const ETH_P_AOE: u32 = 34978;
pub const ETH_P_8021AD: u32 = 34984;
pub const ETH_P_802_EX1: u32 = 34997;
pub const ETH_P_PREAUTH: u32 = 35015;
pub const ETH_P_TIPC: u32 = 35018;
pub const ETH_P_LLDP: u32 = 35020;
pub const ETH_P_MRP: u32 = 35043;
pub const ETH_P_MACSEC: u32 = 35045;
pub const ETH_P_8021AH: u32 = 35047;
pub const ETH_P_MVRP: u32 = 35061;
pub const ETH_P_1588: u32 = 35063;
pub const ETH_P_NCSI: u32 = 35064;
pub const ETH_P_PRP: u32 = 35067;
pub const ETH_P_CFM: u32 = 35074;
pub const ETH_P_FCOE: u32 = 35078;
pub const ETH_P_IBOE: u32 = 35093;
pub const ETH_P_TDLS: u32 = 35085;
pub const ETH_P_FIP: u32 = 35092;
pub const ETH_P_80221: u32 = 35095;
pub const ETH_P_HSR: u32 = 35119;
pub const ETH_P_NSH: u32 = 35151;
pub const ETH_P_LOOPBACK: u32 = 36864;
pub const ETH_P_QINQ1: u32 = 37120;
pub const ETH_P_QINQ2: u32 = 37376;
pub const ETH_P_QINQ3: u32 = 37632;
pub const ETH_P_EDSA: u32 = 56026;
pub const ETH_P_DSA_8021Q: u32 = 56027;
pub const ETH_P_IFE: u32 = 60734;
pub const ETH_P_AF_IUCV: u32 = 64507;
pub const ETH_P_802_3_MIN: u32 = 1536;
pub const ETH_P_802_3: u32 = 1;
pub const ETH_P_AX25: u32 = 2;
pub const ETH_P_ALL: u32 = 3;
pub const ETH_P_802_2: u32 = 4;
pub const ETH_P_SNAP: u32 = 5;
pub const ETH_P_DDCMP: u32 = 6;
pub const ETH_P_WAN_PPP: u32 = 7;
pub const ETH_P_PPP_MP: u32 = 8;
pub const ETH_P_LOCALTALK: u32 = 9;
pub const ETH_P_CAN: u32 = 12;
pub const ETH_P_CANFD: u32 = 13;
pub const ETH_P_PPPTALK: u32 = 16;
pub const ETH_P_TR_802_2: u32 = 17;
pub const ETH_P_MOBITEX: u32 = 21;
pub const ETH_P_CONTROL: u32 = 22;
pub const ETH_P_IRDA: u32 = 23;
pub const ETH_P_ECONET: u32 = 24;
pub const ETH_P_HDLC: u32 = 25;
pub const ETH_P_ARCNET: u32 = 26;
pub const ETH_P_DSA: u32 = 27;
pub const ETH_P_TRAILER: u32 = 28;
pub const ETH_P_PHONET: u32 = 245;
pub const ETH_P_IEEE802154: u32 = 246;
pub const ETH_P_CAIF: u32 = 247;
pub const ETH_P_XDSA: u32 = 248;
pub const ETH_P_MAP: u32 = 249;