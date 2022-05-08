use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::ptr::{null_mut, NonNull};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::{cmp, mem, ptr};

use fxhash::FxHashSet;
use lazy_static::lazy_static;
use libc::{c_int, c_void, dlsym, size_t, RTLD_NEXT};
use parking_lot::Mutex;

macro_rules! rtld_next_fn {
    ($fn:ident, $cache:ident, unsafe extern "C" fn $cfn:ident($($arg:ident: $arg_t:ty),*) $(-> $($ret:tt)+)?) => {
        static $cache: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

        #[allow(unused_unsafe)]
        unsafe fn $fn($($arg: $arg_t),*) $(-> $($ret)+)? {
            let fun = $cache.load(Ordering::SeqCst);
            let fun = NonNull::new(fun)
                .or_else(|| unsafe {
                    let fun = dlsym(RTLD_NEXT, concat!(stringify!($cfn), "\0").as_ptr() as *const i8);

                    $cache.store(fun, Ordering::SeqCst);

                    NonNull::new(fun)
                })
                .expect(concat!("could not resolve ", stringify!($cfn)));
            let fun = unsafe {
                mem::transmute::<_, unsafe extern "C" fn($($arg: $arg_t),*) $(-> $($ret)+)?>(fun.as_ptr())
            };

            fun($($arg),*)
        }
    }
}

rtld_next_fn!(rtld_next_malloc, MALLOC, unsafe extern "C" fn malloc(size: size_t) -> *mut c_void);
rtld_next_fn!(rtld_next_calloc, CALLOC, unsafe extern "C" fn calloc(nobj: size_t, size: size_t) -> *mut c_void);
rtld_next_fn!(rtld_next_posix_memalign, POSIX_MEMALIGN, unsafe extern "C" fn posix_memalign(memptr: *mut *mut c_void, align: size_t, size: size_t) -> c_int);
rtld_next_fn!(rtld_next_aligned_alloc, ALIGNED_ALLOC, unsafe extern "C" fn aligned_alloc(alignment: size_t, size: size_t) -> *mut c_void);
rtld_next_fn!(rtld_next_free, FREE, unsafe extern "C" fn free(p: *mut c_void));
rtld_next_fn!(rtld_next_realloc, REALLOC, unsafe extern "C" fn realloc(p: *mut c_void, size: size_t) -> *mut c_void);
rtld_next_fn!(rtld_next_reallocarray, REALLOC_ARRAY, unsafe extern "C" fn reallocarray(ptr: *mut c_void, nmemb: size_t, size: size_t) -> *mut c_void);

lazy_static! {
    static ref ALLOCS: Mutex<FxHashSet<CVoidPtr>> = <_>::default();
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct CVoidPtr(*mut c_void);

unsafe impl Sync for CVoidPtr {}
unsafe impl Send for CVoidPtr {}

#[no_mangle]
unsafe extern "C" fn malloc(size: size_t) -> *mut c_void {
    let ptr = rtld_next_malloc(size);

    if !ptr.is_null() {
        ALLOCS.lock().insert(CVoidPtr(ptr));
    }

    ptr
}

thread_local! {
    static NEXT_CALLOC_IS_FROM_DLSYM: Cell<bool> = Cell::new(false);
}


#[no_mangle]
unsafe extern "C" fn calloc(nobj: size_t, size: size_t) -> *mut c_void {
    // evil hack because dlsym needs calloc
    let next_calloc_is_from_dlsym =
        NEXT_CALLOC_IS_FROM_DLSYM.with(|next_calloc_is_from_dlsym| next_calloc_is_from_dlsym.get());

    // TODO: add bump allocator to make this slightly more resilient
    // TODO: move this logic into `rtld_next_calloc`?
    if next_calloc_is_from_dlsym {
        NEXT_CALLOC_IS_FROM_DLSYM.with(|in_dlsym| in_dlsym.set(false));

        static mut CALLOC_BUFFER: [u8; 8192] = [0; 8192];

        return &mut CALLOC_BUFFER as *mut _ as *mut c_void;
    }

    if CALLOC.load(Ordering::SeqCst).is_null() {
        NEXT_CALLOC_IS_FROM_DLSYM.with(|in_dlsym| in_dlsym.set(true));
    }

    let ptr = rtld_next_calloc(nobj, size);

    if !ptr.is_null() {
        ALLOCS.lock().insert(CVoidPtr(ptr));
    }

    ptr
}

#[no_mangle]
unsafe extern "C" fn posix_memalign(memptr: *mut *mut c_void, align: size_t, size: size_t) -> c_int {
    let ptr = rtld_next_posix_memalign(memptr, align, size);

    if !memptr.is_null() && !(*memptr).is_null() {
        ALLOCS.lock().insert(CVoidPtr(*memptr));
    }

    ptr
}

#[no_mangle]
unsafe extern "C" fn aligned_alloc(alignment: size_t, size: size_t) -> *mut c_void {
    let ptr = rtld_next_aligned_alloc(alignment, size);

    if !ptr.is_null() {
        ALLOCS.lock().insert(CVoidPtr(ptr));
    }

    ptr
}

#[no_mangle]
unsafe extern "C" fn realloc(orig_ptr: *mut c_void, size: size_t) -> *mut c_void {
    if !orig_ptr.is_null() && !ALLOCS.lock().contains(&CVoidPtr(orig_ptr)) {
        eprintln!("ERROR: trying to reallocate unknown allocation {:p}", orig_ptr);
    }

    let ptr = rtld_next_realloc(orig_ptr, size);

    if !ptr.is_null() && ptr != orig_ptr {
        ALLOCS.lock().insert(CVoidPtr(ptr));
    }

    ptr
}

#[no_mangle]
unsafe extern "C" fn reallocarray(orig_ptr: *mut c_void, nmemb: size_t, size: size_t) -> *mut c_void {
    if !orig_ptr.is_null() && !ALLOCS.lock().contains(&CVoidPtr(orig_ptr)) {
        eprintln!("ERROR: trying to reallocate unknown array allocation {:p}", orig_ptr);
    }

    let ptr = rtld_next_reallocarray(orig_ptr, nmemb, size);

    if !ptr.is_null() && ptr != orig_ptr {
        ALLOCS.lock().insert(CVoidPtr(ptr));
    }

    ptr
}

#[no_mangle]
unsafe extern "C" fn free(p: *mut c_void) {
    if !p.is_null() && !ALLOCS.lock().remove(&CVoidPtr(p)) {
        eprintln!("WARNING: trying to free unknown allocation {:p}", p);
        return;
    }

    rtld_next_free(p)
}


#[global_allocator]
static ALLOC: RTLDNextAlloc = RTLDNextAlloc;

struct RTLDNextAlloc;

// The code below is lifted almost 1:1 from libstd

unsafe impl GlobalAlloc for RTLDNextAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // jemalloc provides alignment less than MIN_ALIGN for small allocations.
        // So only rely on MIN_ALIGN if size >= align.
        // Also see <https://github.com/rust-lang/rust/issues/45955> and
        // <https://github.com/rust-lang/rust/issues/62251#issuecomment-507580914>.
        if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() {
            rtld_next_malloc(layout.size()) as *mut u8
        } else {
            #[cfg(target_os = "macos")]
            {
                if layout.align() > (1 << 31) {
                    return ptr::null_mut();
                }
            }
            aligned_malloc(&layout)
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // See the comment above in `alloc` for why this check looks the way it does.
        if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() {
            rtld_next_calloc(layout.size(), 1) as *mut u8
        } else {
            let ptr = self.alloc(layout);
            if !ptr.is_null() {
                ptr::write_bytes(ptr, 0, layout.size());
            }
            ptr
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        rtld_next_free(ptr as *mut libc::c_void)
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= MIN_ALIGN && layout.align() <= new_size {
            rtld_next_realloc(ptr as *mut libc::c_void, new_size) as *mut u8
        } else {
            realloc_fallback(self, ptr, layout, new_size)
        }
    }
}

unsafe fn aligned_malloc(layout: &Layout) -> *mut u8 {
    let mut out = ptr::null_mut();
    // posix_memalign requires that the alignment be a multiple of `sizeof(void*)`.
    // Since these are all powers of 2, we can just use max.
    let align = layout.align().max(mem::size_of::<usize>());
    let ret = rtld_next_posix_memalign(&mut out, align, layout.size());
    if ret != 0 {
        ptr::null_mut()
    } else {
        out as *mut u8
    }
}

unsafe fn realloc_fallback(
    alloc: &RTLDNextAlloc,
    ptr: *mut u8,
    old_layout: Layout,
    new_size: usize,
) -> *mut u8 {
    // Docs for GlobalAlloc::realloc require this to be valid:
    let new_layout = Layout::from_size_align_unchecked(new_size, old_layout.align());

    let new_ptr = GlobalAlloc::alloc(alloc, new_layout);
    if !new_ptr.is_null() {
        let size = cmp::min(old_layout.size(), new_size);
        ptr::copy_nonoverlapping(ptr, new_ptr, size);
        GlobalAlloc::dealloc(alloc, ptr, old_layout);
    }
    new_ptr
}

#[cfg(all(any(
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "mips",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc",
    target_arch = "asmjs",
    target_arch = "wasm32",
    target_arch = "hexagon",
    all(target_arch = "riscv32", not(target_os = "espidf")),
    all(target_arch = "xtensa", not(target_os = "espidf")),
)))]
const MIN_ALIGN: usize = 8;
#[cfg(all(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "mips64",
    target_arch = "s390x",
    target_arch = "sparc64",
    target_arch = "riscv64",
    target_arch = "wasm64",
)))]
const MIN_ALIGN: usize = 16;
