use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, OnceLock,
};

use libafl_qemu::GuestAddr;

pub const UPACK_MODULE_WORKER_OFF: GuestAddr = 0x840;
pub const UPACK_ENTRY_STUB_LEN: usize = 0x300;
pub const UPACK_MAX_STREAM_LEN: usize = 0x200000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpackReadSpec {
    pub seek_callsite: GuestAddr,
    pub read_callsite: GuestAddr,
    pub size: usize,
    pub bit: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UpackReadWindow {
    pub read_callsite: GuestAddr,
    pub stream_offset: usize,
    pub size: usize,
}

pub const UPACK_READ_SPECS: &[UpackReadSpec] = &[
    UpackReadSpec {
        seek_callsite: 0x8da,
        read_callsite: 0x903,
        size: 0x300,
        bit: 0,
    },
    UpackReadSpec {
        seek_callsite: 0xb7f,
        read_callsite: 0xb92,
        size: 0x4,
        bit: 1,
    },
    UpackReadSpec {
        seek_callsite: 0xbbd,
        read_callsite: 0xbd0,
        size: 0x4,
        bit: 2,
    },
    UpackReadSpec {
        seek_callsite: 0xc27,
        read_callsite: 0xc3a,
        size: 0x1,
        bit: 3,
    },
    UpackReadSpec {
        seek_callsite: 0xcc4,
        read_callsite: 0xcd6,
        size: 0x35,
        bit: 4,
    },
    UpackReadSpec {
        seek_callsite: 0xd23,
        read_callsite: 0xd35,
        size: 0x4,
        bit: 5,
    },
    UpackReadSpec {
        seek_callsite: 0xdc9,
        read_callsite: 0xddb,
        size: 0x50,
        bit: 6,
    },
    UpackReadSpec {
        seek_callsite: 0xe1b,
        read_callsite: 0xe2d,
        size: 0xc,
        bit: 7,
    },
    UpackReadSpec {
        seek_callsite: 0xe79,
        read_callsite: 0xe8b,
        size: 0x4,
        bit: 8,
    },
    UpackReadSpec {
        seek_callsite: 0xeaf,
        read_callsite: 0xec1,
        size: 0x4,
        bit: 9,
    },
    UpackReadSpec {
        seek_callsite: 0xeec,
        read_callsite: 0xefe,
        size: 0x4,
        bit: 10,
    },
    UpackReadSpec {
        seek_callsite: 0xf88,
        read_callsite: 0xf9b,
        size: 0x1,
        bit: 11,
    },
    UpackReadSpec {
        seek_callsite: 0xfc1,
        read_callsite: 0xfd4,
        size: 0x1,
        bit: 12,
    },
    UpackReadSpec {
        seek_callsite: 0x1008,
        read_callsite: 0x101b,
        size: 0x4,
        bit: 13,
    },
    UpackReadSpec {
        seek_callsite: 0x105d,
        read_callsite: 0x106f,
        size: 0x48,
        bit: 14,
    },
    UpackReadSpec {
        seek_callsite: 0x10b9,
        read_callsite: 0x10cb,
        size: 0x50,
        bit: 15,
    },
    UpackReadSpec {
        seek_callsite: 0x1118,
        read_callsite: 0x112a,
        size: 0x68,
        bit: 16,
    },
    UpackReadSpec {
        seek_callsite: 0x117a,
        read_callsite: 0x118c,
        size: 0x60,
        bit: 17,
    },
    UpackReadSpec {
        seek_callsite: 0x11dd,
        read_callsite: 0x11ef,
        size: 0x80,
        bit: 18,
    },
    UpackReadSpec {
        seek_callsite: 0x1244,
        read_callsite: 0x1256,
        size: 0xc4,
        bit: 19,
    },
    UpackReadSpec {
        seek_callsite: 0x12a8,
        read_callsite: 0x12ba,
        size: 0x3c,
        bit: 20,
    },
    UpackReadSpec {
        seek_callsite: 0x12f9,
        read_callsite: 0x130b,
        size: 0x30,
        bit: 21,
    },
];

static UNLOCKED_READS: AtomicU64 = AtomicU64::new(0);
static WINDOWS: OnceLock<Mutex<Vec<UpackReadWindow>>> = OnceLock::new();

fn windows() -> &'static Mutex<Vec<UpackReadWindow>> {
    WINDOWS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn read_spec(read_callsite: GuestAddr) -> Option<&'static UpackReadSpec> {
    UPACK_READ_SPECS
        .iter()
        .find(|spec| spec.read_callsite == read_callsite)
}

pub fn record_read_window(read_callsite: GuestAddr, stream_offset: usize, size: usize) {
    let Some(spec) = read_spec(read_callsite) else {
        return;
    };
    if size == 0 || stream_offset >= UPACK_MAX_STREAM_LEN {
        return;
    }

    let size = size
        .min(spec.size)
        .min(UPACK_MAX_STREAM_LEN - stream_offset);
    UNLOCKED_READS.fetch_or(1u64 << spec.bit, Ordering::Relaxed);

    let window = UpackReadWindow {
        read_callsite,
        stream_offset,
        size,
    };
    let mut known = windows().lock().expect("UPack progress mutex poisoned");
    if !known.contains(&window) {
        known.push(window);
    }
}

pub fn unlocked_mask() -> u64 {
    UNLOCKED_READS.load(Ordering::Relaxed)
}

pub fn snapshot_windows() -> Vec<UpackReadWindow> {
    windows()
        .lock()
        .expect("UPack progress mutex poisoned")
        .clone()
}

pub fn seed_bootstrap_windows() {
    record_read_window(0x118c, 0x188, 0x60);
    record_read_window(0xddb, 0xa0, 0x50);
}
