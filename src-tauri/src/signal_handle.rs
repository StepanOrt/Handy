use log::warn;
use tauri::{AppHandle, Manager};

/// Send a transcription input to the coordinator.
/// Used by signal handlers, CLI flags, and any other external trigger.
pub fn send_transcription_input(app: &AppHandle, binding_id: &str, source: &str) {
    if let Some(c) = app.try_state::<crate::TranscriptionCoordinator>() {
        c.send_external_input(binding_id, source);
    } else {
        warn!("TranscriptionCoordinator not initialized");
    }
}

// ============================================================================
// Linux: WebKitGTK-Safe Signal Handling
// ============================================================================
//
// On Linux, WebKitGTK's JavaScriptCore GC uses POSIX signals (SIGUSR1 by default,
// or whatever signal is configured in JSC_SIGNAL_FOR_GC) to suspend and resume
// its own threads via pthread_kill/tgkill.
//
// WebKit's signal handler (`Thread::signalHandlerSuspendResume`) unconditionally
// dereferences `targetThread.load()->m_suspendCount`. When an external process
// sends a signal (such as `pkill -USR1 -x handy` or `pkill -USR2 -x handy`),
// `targetThread` is NULL, causing an immediate SIGSEGV segmentation fault.
//
// Furthermore, if Handy were to naively listen to SIGUSR1 without inspecting
// signal origins, WebKit's internal GC cycles would trigger phantom recordings
// every few minutes (#1660).
//
// To solve both issues completely:
// 1. We interpose `sigaction` and wrap SIGUSR1 and SIGUSR2.
// 2. In the signal handler, we inspect `siginfo_t`:
//    - If `si_code == SI_TKILL` and `si_pid == getpid()`: it is an internal GC
//      thread-suspension signal from WebKit. We forward it to WebKit's saved
//      action and do NOT trigger transcription.
//    - Otherwise: it is an external signal (from `pkill`, `kill`, shortcuts).
//      We DO NOT call WebKit's handler (preventing the NULL dereference crash),
//      and instead dispatch to Handy's TranscriptionCoordinator via a self-pipe.
#[cfg(target_os = "linux")]
mod linux_signal {
    use super::send_transcription_input;
    use log::{debug, warn};
    use std::cell::UnsafeCell;
    use std::os::raw::{c_int, c_void};
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
    use std::thread;
    use tauri::AppHandle;

    const MAX_SIGNALS: usize = 64;

    struct WebKitActionSlot {
        action: UnsafeCell<libc::sigaction>,
        installed: AtomicBool,
    }

    unsafe impl Sync for WebKitActionSlot {}

    impl WebKitActionSlot {
        const fn new() -> Self {
            Self {
                action: UnsafeCell::new(unsafe { std::mem::zeroed() }),
                installed: AtomicBool::new(false),
            }
        }
    }

    static SAVED_WEBKIT_ACTIONS: [WebKitActionSlot; MAX_SIGNALS] =
        [const { WebKitActionSlot::new() }; MAX_SIGNALS];

    static REAL_SIGACTION: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    static PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

    unsafe fn get_real_sigaction(
    ) -> extern "C" fn(c_int, *const libc::sigaction, *mut libc::sigaction) -> c_int {
        let mut ptr = REAL_SIGACTION.load(Ordering::Acquire);
        if ptr.is_null() {
            let sym = libc::dlsym(libc::RTLD_NEXT, c"sigaction".as_ptr());
            REAL_SIGACTION.store(sym, Ordering::Release);
            ptr = sym;
        }
        std::mem::transmute(ptr)
    }

    unsafe extern "C" fn handy_sigaction_wrapper(
        sig: c_int,
        info: *mut libc::siginfo_t,
        ucontext: *mut c_void,
    ) {
        let is_internal_gc = if info.is_null() {
            false
        } else {
            (*info).si_code == libc::SI_TKILL && (*info).si_pid() == libc::getpid()
        };

        if is_internal_gc {
            let sig_idx = sig as usize;
            if sig_idx < MAX_SIGNALS
                && SAVED_WEBKIT_ACTIONS[sig_idx]
                    .installed
                    .load(Ordering::Acquire)
            {
                let old = &*SAVED_WEBKIT_ACTIONS[sig_idx].action.get();
                if (old.sa_flags & libc::SA_SIGINFO) != 0 {
                    let action: extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void) =
                        std::mem::transmute(old.sa_sigaction);
                    action(sig, info, ucontext);
                } else if old.sa_sigaction != 0 && old.sa_sigaction != 1 {
                    let handler: extern "C" fn(c_int) = std::mem::transmute(old.sa_sigaction);
                    handler(sig);
                }
            }
        } else {
            let write_fd = PIPE_WRITE_FD.load(Ordering::Relaxed);
            if write_fd >= 0 {
                let byte = sig as u8;
                libc::write(write_fd, &byte as *const u8 as *const c_void, 1);
            }
        }
    }

    unsafe fn install_wrapper(sig: c_int) {
        let real_fn = get_real_sigaction();
        let mut wrap: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut wrap.sa_mask);
        wrap.sa_sigaction = handy_sigaction_wrapper as *const () as usize;
        wrap.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        real_fn(sig, &wrap, std::ptr::null_mut());
    }

    #[no_mangle]
    pub unsafe extern "C" fn sigaction(
        sig: c_int,
        act: *const libc::sigaction,
        oact: *mut libc::sigaction,
    ) -> c_int {
        let real_fn = get_real_sigaction();
        if sig == libc::SIGUSR1 || sig == libc::SIGUSR2 {
            let sig_idx = sig as usize;
            if act.is_null() && !oact.is_null() {
                if sig_idx < MAX_SIGNALS
                    && SAVED_WEBKIT_ACTIONS[sig_idx]
                        .installed
                        .load(Ordering::Acquire)
                {
                    *oact = *SAVED_WEBKIT_ACTIONS[sig_idx].action.get();
                } else {
                    std::ptr::write_bytes(oact, 0, 1);
                }
                return 0;
            }
            if !act.is_null() {
                if (*act).sa_sigaction != handy_sigaction_wrapper as *const () as usize
                    && sig_idx < MAX_SIGNALS
                {
                    *SAVED_WEBKIT_ACTIONS[sig_idx].action.get() = *act;
                    SAVED_WEBKIT_ACTIONS[sig_idx]
                        .installed
                        .store(true, Ordering::Release);
                }
                if !oact.is_null() && sig_idx < MAX_SIGNALS {
                    *oact = *SAVED_WEBKIT_ACTIONS[sig_idx].action.get();
                }
                install_wrapper(sig);
                return 0;
            }
            return 0;
        }
        real_fn(sig, act, oact)
    }

    pub fn setup_signal_handler(app_handle: AppHandle) {
        let mut pipe_fds = [0; 2];
        unsafe {
            if libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
                warn!(
                    "Failed to create signal pipe: {}",
                    std::io::Error::last_os_error()
                );
                return;
            }
            PIPE_WRITE_FD.store(pipe_fds[1], Ordering::SeqCst);

            let real_fn = get_real_sigaction();
            for &sig in &[libc::SIGUSR1, libc::SIGUSR2] {
                let sig_idx = sig as usize;
                let mut current: libc::sigaction = std::mem::zeroed();
                if real_fn(sig, std::ptr::null(), &mut current) == 0
                    && current.sa_sigaction != 0
                    && current.sa_sigaction != 1
                    && current.sa_sigaction != handy_sigaction_wrapper as *const () as usize
                {
                    *SAVED_WEBKIT_ACTIONS[sig_idx].action.get() = current;
                    SAVED_WEBKIT_ACTIONS[sig_idx]
                        .installed
                        .store(true, Ordering::Release);
                }
                install_wrapper(sig);
            }
        }

        debug!("Signal handlers registered (SIGUSR1, SIGUSR2 with WebKit-safe forwarding)");

        let read_fd = pipe_fds[0];
        thread::spawn(move || {
            let mut buf = [0u8; 16];
            unsafe {
                libc::fcntl(read_fd, libc::F_SETFL, 0);
            }
            loop {
                let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
                for &sig in &buf[..n as usize] {
                    let (binding_id, signal_name) = match sig as c_int {
                        libc::SIGUSR1 => ("transcribe_with_post_process", "SIGUSR1"),
                        libc::SIGUSR2 => ("transcribe", "SIGUSR2"),
                        _ => continue,
                    };
                    debug!("Received external signal {signal_name}");
                    send_transcription_input(&app_handle, binding_id, signal_name);
                }
            }
        });
    }
}

// ============================================================================
// macOS & other Unix platforms
// ============================================================================
#[cfg(target_os = "macos")]
mod other_unix_signal {
    use super::send_transcription_input;
    use log::debug;
    use signal_hook::consts::{SIGUSR1, SIGUSR2};
    use signal_hook::iterator::Signals;
    use std::thread;
    use tauri::AppHandle;

    pub fn setup_signal_handler(app_handle: AppHandle) {
        let mut signals = Signals::new([SIGUSR1, SIGUSR2])
            .expect("failed to register transcription signal handlers");
        debug!("Signal handlers registered (SIGUSR1, SIGUSR2)");
        thread::spawn(move || {
            for sig in signals.forever() {
                let (binding_id, signal_name) = match sig {
                    SIGUSR1 => ("transcribe_with_post_process", "SIGUSR1"),
                    SIGUSR2 => ("transcribe", "SIGUSR2"),
                    _ => continue,
                };
                debug!("Received {signal_name}");
                send_transcription_input(&app_handle, binding_id, signal_name);
            }
        });
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
mod other_unix_signal {
    use super::send_transcription_input;
    use log::debug;
    use signal_hook::consts::{SIGUSR1, SIGUSR2};
    use signal_hook::iterator::Signals;
    use std::thread;
    use tauri::AppHandle;

    pub fn setup_signal_handler(app_handle: AppHandle) {
        let mut signals = Signals::new([SIGUSR1, SIGUSR2])
            .expect("failed to register transcription signal handlers");
        debug!("Signal handlers registered (SIGUSR1, SIGUSR2)");
        thread::spawn(move || {
            for sig in signals.forever() {
                let (binding_id, signal_name) = match sig {
                    SIGUSR1 => ("transcribe_with_post_process", "SIGUSR1"),
                    SIGUSR2 => ("transcribe", "SIGUSR2"),
                    _ => continue,
                };
                debug!("Received {signal_name}");
                send_transcription_input(&app_handle, binding_id, signal_name);
            }
        });
    }
}

#[cfg(target_os = "linux")]
pub use linux_signal::setup_signal_handler;

#[cfg(all(unix, not(target_os = "linux")))]
pub use other_unix_signal::setup_signal_handler;
