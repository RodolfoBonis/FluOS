//! Userspace bring-up: loading an ELF into a process, building its initial
//! stack (argv/envp/auxv the way musl expects), and entering ring 3.
//!
//! For the M4 self-test it also carries a tiny, self-contained raw-syscall
//! "hello world" ELF built in [`hello_elf`], so the user-mode path (address
//! space, ELF load, `syscall`/`sysret`) can be verified with no external
//! toolchain or initramfs.

use crate::arch::x86_64::user;
use crate::fs::FdTable;
use crate::process::{self, AddressSpace, Process};
use crate::sync::SpinLock;
use crate::{elf, scheduler};
use abi::types::{
    AT_BASE, AT_CLKTCK, AT_EGID, AT_ENTRY, AT_EUID, AT_EXECFN, AT_GID, AT_HWCAP, AT_NULL, AT_PAGESZ,
    AT_PHDR, AT_PHENT, AT_PHNUM, AT_RANDOM, AT_SECURE, AT_UID,
};
use abi::Errno;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

/// Top of the initial user stack (just below the non-canonical hole).
const STACK_TOP: u64 = 0x7fff_ffff_f000;
/// Initial user stack size.
const STACK_SIZE: u64 = 0x40000;
/// Total main-thread stack reservation (Linux's default RLIMIT_STACK). Only
/// [`STACK_SIZE`] is mapped up front; the rest is demand-paged. musl measures
/// the main stack by probing this reservation, and Rust's stack-overflow guards
/// (e.g. starship's parser) rely on that measurement.
const STACK_RESERVE: u64 = 8 * 1024 * 1024;

/// Entry parameters handed to the user thread's trampoline.
struct UserEntry {
    entry: u64,
    user_sp: u64,
}

/// Loads `elf` into a fresh process, builds its stack, and schedules a thread
/// that enters user mode. Returns the process handle.
pub fn spawn(elf_image: &[u8], argv: &[&str], envp: &[&str]) -> Result<Arc<SpinLock<Process>>, Errno> {
    spawn_as(elf_image, argv, envp, 0, 0)
}

/// Spawns a user process running as `uid`/`gid` (0,0 for the selftests; a real
/// user for the login shell). The ids are set before the thread is enqueued.
pub fn spawn_as(
    elf_image: &[u8],
    argv: &[&str],
    envp: &[&str],
    uid: u32,
    gid: u32,
) -> Result<Arc<SpinLock<Process>>, Errno> {
    let proc = Process::new().ok_or(Errno::ENOMEM)?;
    let (entry, user_sp, cr3) = {
        let mut p = proc.lock();
        let loaded = elf::load(&mut p.space, elf_image)?;
        let user_sp = build_stack(&mut p.space, &loaded, argv, envp)?;
        p.fds = FdTable::with_stdio();
        p.uid = uid;
        p.gid = gid;
        (loaded.entry, user_sp, p.space.cr3())
    };

    process::register(proc.clone());
    let ue = Box::leak(Box::new(UserEntry { entry, user_sp }));
    let ptr = Arc::as_ptr(&proc) as u64;

    let pid = proc.lock().pid;
    let ctx = scheduler::UserContext {
        cr3,
        proc_ptr: ptr,
        fs_base: 0,
        user_gs: 0,
        linux_tid: pid,
        clear_child_tid: 0,
    };
    let tid = scheduler::spawn_user(user_thread_start, core::ptr::from_mut(ue) as usize, 0, crate::percpu::cpu_id(), ctx)?;
    proc.lock().main_thread = tid as u64;
    Ok(proc)
}

/// Trampoline run as a kernel thread; the scheduler's `switch_mm` has already
/// installed this process's CR3, kernel stack, and current-process pointer, so
/// it only needs to drop into user mode.
/// Parameters for a fork child's entry trampoline.
pub struct ForkEntry {
    pub regs: crate::arch::x86_64::user::Regs,
}

/// Trampoline for a fork child: resumes the parent's register state (rax=0).
extern "C" fn fork_child_start(arg: usize) {
    let e = unsafe { &*(arg as *const ForkEntry) };
    unsafe { user::enter_user_regs(&e.regs) };
}

/// Spawns a fork child thread that resumes `regs` (with rax already 0).
pub fn spawn_fork_child(child: &Arc<SpinLock<Process>>, regs: crate::arch::x86_64::user::Regs) -> Result<(), Errno> {
    let entry = Box::leak(Box::new(ForkEntry { regs }));
    let cr3 = child.lock().space.cr3();
    let ptr = Arc::as_ptr(child) as u64;
    // SAFETY: `tid` is the freshly spawned, live thread; it inherits the parent
    // thread's TLS (FS) and user GS bases so the copied TLS stays valid.
    use x86_64::registers::model_specific::{FsBase, KernelGsBase};
    let child_pid = child.lock().pid;
    let ctx = scheduler::UserContext {
        cr3,
        proc_ptr: ptr,
        fs_base: FsBase::read().as_u64(),
        user_gs: KernelGsBase::read().as_u64(),
        linux_tid: child_pid,
        clear_child_tid: 0,
    };
    let tid = scheduler::spawn_user(fork_child_start, core::ptr::from_mut(entry) as usize, 0, crate::percpu::cpu_id(), ctx)?;
    child.lock().main_thread = tid as u64;
    Ok(())
}

/// Spawns a `clone(CLONE_VM)` thread that shares `cr3`/`proc` with its creator
/// and resumes `regs` (rax already 0) on its own stack, with its own TLS (`fs`),
/// Linux tid, and optional clear-child-tid pointer.
pub fn spawn_thread(
    regs: crate::arch::x86_64::user::Regs,
    cr3: u64,
    proc_ptr: u64,
    fs: u64,
    user_gs: u64,
    linux_tid: i32,
    clear_child_tid: u64,
) -> Result<(), Errno> {
    let entry = Box::leak(Box::new(ForkEntry { regs }));
    let ctx = scheduler::UserContext { cr3, proc_ptr, fs_base: fs, user_gs, linux_tid, clear_child_tid };
    scheduler::spawn_user(fork_child_start, core::ptr::from_mut(entry) as usize, 0, crate::percpu::cpu_id(), ctx)?;
    Ok(())
}

extern "C" fn user_thread_start(arg: usize) {
    // SAFETY: `arg` is the leaked `UserEntry` for this thread.
    let ue = unsafe { &*(arg as *const UserEntry) };
    // SAFETY: entry/user_sp are valid user addresses in the active space.
    unsafe { user::enter_user(ue.entry, ue.user_sp) };
}

/// Builds the initial user stack: the strings block (argv, envp, 16 random
/// bytes for `AT_RANDOM`, the exec filename) at the top, then the argc/argv/
/// envp/auxv vector below it, 16-byte aligned. Returns the initial `rsp`.
pub fn build_stack(space: &mut AddressSpace, loaded: &elf::Loaded, argv: &[&str], envp: &[&str]) -> Result<u64, Errno> {
    space.map_region(STACK_TOP - STACK_SIZE, STACK_SIZE, true, false);
    space.reserve_region(STACK_TOP - STACK_RESERVE, STACK_RESERVE - STACK_SIZE, true, false);

    let mut strings: Vec<u8> = Vec::new();
    let mut argv_off: Vec<usize> = Vec::new();
    for s in argv {
        argv_off.push(strings.len());
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
    }
    let mut envp_off: Vec<usize> = Vec::new();
    for s in envp {
        envp_off.push(strings.len());
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
    }
    let rand_off = strings.len();
    let mut rnd = [0u8; 16];
    crate::rng::fill(&mut rnd);
    strings.extend_from_slice(&rnd);
    let execfn_off = strings.len();
    strings.extend_from_slice(argv.first().map_or(b"".as_slice(), |s| s.as_bytes()));
    strings.push(0);

    let strings_base = (STACK_TOP - strings.len() as u64) & !0xF;
    space.write(strings_base, &strings);
    let at = |off: usize| strings_base + off as u64;

    let aux: [(u64, u64); 15] = [
        (AT_PHDR, loaded.phdr),
        (AT_PHENT, loaded.phent),
        (AT_PHNUM, loaded.phnum),
        (AT_PAGESZ, 4096),
        (AT_ENTRY, loaded.entry),
        (AT_BASE, loaded.base),
        (AT_RANDOM, at(rand_off)),
        (AT_HWCAP, 0),
        (AT_CLKTCK, 100),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_EXECFN, at(execfn_off)),
    ];

    let mut vec: Vec<u64> = Vec::new();
    vec.push(argv.len() as u64);
    for &o in &argv_off {
        vec.push(at(o));
    }
    vec.push(0);
    for &o in &envp_off {
        vec.push(at(o));
    }
    vec.push(0);
    for (t, v) in aux {
        vec.push(t);
        vec.push(v);
    }
    vec.push(AT_NULL);
    vec.push(0);

    let vec_bytes = vec.len() * 8;
    let rsp = (strings_base - vec_bytes as u64) & !0xF;
    let mut bytes = Vec::with_capacity(vec_bytes);
    for v in &vec {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    space.write(rsp, &bytes);
    Ok(rsp)
}

/// Builds a tiny static ELF that writes a greeting and `exit_group(0)`s, used by
/// the self-test. Entirely self-contained (no toolchain needed).
pub fn hello_elf() -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let msg: &[u8] = b"hello from FluOS userspace\n";
    let headers = 64 + 56u64;

    // Machine code (36 bytes); `msg` lives right after it.
    let code_len = 36u64;
    let msg_addr = V + headers + code_len;
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0xB8, 1, 0, 0, 0]); // mov eax, 1 (write)
    code.extend_from_slice(&[0xBF, 1, 0, 0, 0]); // mov edi, 1 (stdout)
    code.push(0x48);
    code.push(0xBE); // movabs rsi, imm64
    code.extend_from_slice(&msg_addr.to_le_bytes());
    code.push(0xBA); // mov edx, imm32 (len)
    code.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    code.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]); // mov eax, 231 (exit_group)
    code.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    debug_assert_eq!(code.len() as u64, code_len);

    let filesz = headers + code_len + msg.len() as u64;
    let entry = V + headers;

    let mut elf = Vec::new();
    // ELF header.
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]); // e_ident padding
    push_u16(&mut elf, 2); // e_type = ET_EXEC
    push_u16(&mut elf, 62); // e_machine = x86_64
    push_u32(&mut elf, 1); // e_version
    push_u64(&mut elf, entry); // e_entry
    push_u64(&mut elf, 64); // e_phoff
    push_u64(&mut elf, 0); // e_shoff
    push_u32(&mut elf, 0); // e_flags
    push_u16(&mut elf, 64); // e_ehsize
    push_u16(&mut elf, 56); // e_phentsize
    push_u16(&mut elf, 1); // e_phnum
    push_u16(&mut elf, 0); // e_shentsize
    push_u16(&mut elf, 0); // e_shnum
    push_u16(&mut elf, 0); // e_shstrndx
    // Program header.
    push_u32(&mut elf, 1); // p_type = PT_LOAD
    push_u32(&mut elf, 7); // p_flags = RWX
    push_u64(&mut elf, 0); // p_offset
    push_u64(&mut elf, V); // p_vaddr
    push_u64(&mut elf, V); // p_paddr
    push_u64(&mut elf, filesz); // p_filesz
    push_u64(&mut elf, filesz); // p_memsz
    push_u64(&mut elf, 0x1000); // p_align
    elf.extend_from_slice(&code);
    elf.extend_from_slice(msg);
    elf
}

fn push_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn push_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn push_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Builds a static ELF that calls `getpid` `n` times then `exit_group(0)`, for
/// the syscall round-trip benchmark.
pub fn getpid_loop_elf(n: u32) -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let headers = 64 + 56u64;
    let mut code: Vec<u8> = Vec::new();
    code.push(0xBB); // mov ebx, imm32 (loop count)
    code.extend_from_slice(&n.to_le_bytes());
    // loop: mov eax,39 (getpid); syscall; dec ebx; jnz loop
    code.extend_from_slice(&[0xB8, 0x27, 0, 0, 0]);
    code.extend_from_slice(&[0x0F, 0x05]);
    code.extend_from_slice(&[0xFF, 0xCB]); // dec ebx
    code.extend_from_slice(&[0x75, 0xF5]); // jnz -11
    // exit_group(0)
    code.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]);
    code.extend_from_slice(&[0x31, 0xFF]);
    code.extend_from_slice(&[0x0F, 0x05]);

    let filesz = headers + code.len() as u64;
    let entry = V + headers;
    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]);
    push_u16(&mut elf, 2);
    push_u16(&mut elf, 62);
    push_u32(&mut elf, 1);
    push_u64(&mut elf, entry);
    push_u64(&mut elf, 64);
    push_u64(&mut elf, 0);
    push_u32(&mut elf, 0);
    push_u16(&mut elf, 64);
    push_u16(&mut elf, 56);
    push_u16(&mut elf, 1);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u32(&mut elf, 1);
    push_u32(&mut elf, 5); // R+X
    push_u64(&mut elf, 0);
    push_u64(&mut elf, V);
    push_u64(&mut elf, V);
    push_u64(&mut elf, filesz);
    push_u64(&mut elf, filesz);
    push_u64(&mut elf, 0x1000);
    elf.extend_from_slice(&code);
    elf
}

/// Wraps raw machine code in a minimal single-segment RWX `ET_EXEC` image loaded
/// at `0x40_0000`, entering at the first instruction. Used by the ring-3
/// security self-tests, which are a few hand-assembled bytes each.
fn raw_exec_elf(code: &[u8]) -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let headers = 64 + 56u64;
    let filesz = headers + code.len() as u64;
    let entry = V + headers;
    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]);
    push_u16(&mut elf, 2); // ET_EXEC
    push_u16(&mut elf, 62); // x86_64
    push_u32(&mut elf, 1);
    push_u64(&mut elf, entry);
    push_u64(&mut elf, 64); // e_phoff
    push_u64(&mut elf, 0);
    push_u32(&mut elf, 0);
    push_u16(&mut elf, 64);
    push_u16(&mut elf, 56);
    push_u16(&mut elf, 1);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u32(&mut elf, 1); // PT_LOAD
    push_u32(&mut elf, 7); // RWX (the bad-store test writes; all execute)
    push_u64(&mut elf, 0);
    push_u64(&mut elf, V);
    push_u64(&mut elf, V);
    push_u64(&mut elf, filesz);
    push_u64(&mut elf, filesz);
    push_u64(&mut elf, 0x1000);
    elf.extend_from_slice(code);
    elf
}

/// `exit_group(0)` — mov eax,231; xor edi,edi; syscall.
fn push_exit_group(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]);
    code.extend_from_slice(&[0x31, 0xFF]);
    code.extend_from_slice(&[0x0F, 0x05]);
}

/// `ud2`: an illegal instruction (#UD). The kernel must kill the process with
/// SIGILL, not panic.
fn ud2_elf() -> Vec<u8> {
    raw_exec_elf(&[0x0F, 0x0B])
}

/// Stores to an unmapped user address (4 GiB, well below `USER_MAX`). The #PF
/// must become a SIGSEGV kill, not a kernel panic.
fn bad_store_elf() -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0x48);
    code.push(0xB8); // movabs rax, 0x1_0000_0000
    code.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
    code.extend_from_slice(&[0xC6, 0x00, 0x00]); // mov byte ptr [rax], 0
    raw_exec_elf(&code)
}

/// `write(1, 0x40_0000, 1 << 40)`: a user-controlled, absurd length. The kernel
/// must bound it (no `vec![0u8; 1<<40]`), survive, and the process exits cleanly.
fn huge_write_elf() -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let mut code = Vec::new();
    code.extend_from_slice(&[0xB8, 1, 0, 0, 0]); // mov eax, 1 (write)
    code.extend_from_slice(&[0xBF, 1, 0, 0, 0]); // mov edi, 1 (stdout)
    code.push(0x48);
    code.push(0xBE); // movabs rsi, V (mapped buffer)
    code.extend_from_slice(&V.to_le_bytes());
    code.push(0x48);
    code.push(0xBA); // movabs rdx, 1 << 40
    code.extend_from_slice(&(1u64 << 40).to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    push_exit_group(&mut code);
    raw_exec_elf(&code)
}

/// `arch_prctl(ARCH_SET_FS, 0x8000_0000_0000_0000)`: a non-canonical,
/// kernel-half FS base. The kernel must reject it with EINVAL (never load it)
/// and the process exits cleanly.
fn bad_setfs_elf() -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0xB8, 158, 0, 0, 0]); // mov eax, 158 (arch_prctl)
    code.extend_from_slice(&[0xBF, 0x02, 0x10, 0, 0]); // mov edi, 0x1002 (ARCH_SET_FS)
    code.push(0x48);
    code.push(0xBE); // movabs rsi, 0x8000_0000_0000_0000
    code.extend_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    push_exit_group(&mut code);
    raw_exec_elf(&code)
}

/// Builds a single-RWX-segment `ET_EXEC` image with an explicit entry offset
/// (used by the signal self-test, whose entry is past its handler/restorer).
fn raw_exec_elf_at(code: &[u8], entry: u64) -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let headers = 64 + 56u64;
    let filesz = headers + code.len() as u64;
    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]);
    push_u16(&mut elf, 2);
    push_u16(&mut elf, 62);
    push_u32(&mut elf, 1);
    push_u64(&mut elf, entry);
    push_u64(&mut elf, 64);
    push_u64(&mut elf, 0);
    push_u32(&mut elf, 0);
    push_u16(&mut elf, 64);
    push_u16(&mut elf, 56);
    push_u16(&mut elf, 1);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u32(&mut elf, 1);
    push_u32(&mut elf, 7); // RWX
    push_u64(&mut elf, 0);
    push_u64(&mut elf, V);
    push_u64(&mut elf, V);
    push_u64(&mut elf, filesz);
    push_u64(&mut elf, filesz);
    push_u64(&mut elf, 0x1000);
    elf.extend_from_slice(code);
    elf
}

/// Builds a program that installs a SIGUSR1 handler, sends SIGUSR1 to itself,
/// and — after the handler returns via `rt_sigreturn` — continues. The handler
/// writes `H`; main then writes `D`. Observing `HD` proves the whole path:
/// `rt_sigaction`, delivery of a caught signal, the on-stack signal frame, and
/// `rt_sigreturn` restoring the interrupted context.
fn signal_handler_elf() -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let headers = 64 + 56u64;

    // handler: push 'H'; write(1, rsp, 1); add rsp,8; ret.
    let handler: Vec<u8> = vec![
        0xB8, 0x48, 0, 0, 0, // mov eax, 'H'
        0x50, // push rax
        0xB8, 1, 0, 0, 0, // mov eax, 1 (write)
        0xBF, 1, 0, 0, 0, // mov edi, 1
        0x48, 0x89, 0xE6, // mov rsi, rsp
        0xBA, 1, 0, 0, 0, // mov edx, 1
        0x0F, 0x05, // syscall
        0x48, 0x83, 0xC4, 0x08, // add rsp, 8
        0xC3, // ret -> restorer (pretcode)
    ];
    // restorer: mov eax,15 (rt_sigreturn); syscall.
    let restorer: Vec<u8> = vec![0xB8, 0x0F, 0, 0, 0, 0x0F, 0x05];

    let handler_addr = V + headers;
    let restorer_addr = handler_addr + handler.len() as u64;
    let entry = restorer_addr + restorer.len() as u64;

    let mut main: Vec<u8> = Vec::new();
    main.extend_from_slice(&[0x48, 0x83, 0xEC, 0x40]); // sub rsp, 64
    main.extend_from_slice(&[0x48, 0xB8]); // movabs rax, handler_addr
    main.extend_from_slice(&handler_addr.to_le_bytes());
    main.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp], rax
    main.extend_from_slice(&[0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x14]); // mov dword [rsp+8], 0x14000000
    main.extend_from_slice(&[0xC7, 0x44, 0x24, 0x0C, 0x00, 0x00, 0x00, 0x00]); // mov dword [rsp+12], 0
    main.extend_from_slice(&[0x48, 0xB8]); // movabs rax, restorer_addr
    main.extend_from_slice(&restorer_addr.to_le_bytes());
    main.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x10]); // mov [rsp+16], rax
    main.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    main.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+24], rax (mask=0)
    main.extend_from_slice(&[0xB8, 13, 0, 0, 0]); // mov eax, 13 (rt_sigaction)
    main.extend_from_slice(&[0xBF, 10, 0, 0, 0]); // mov edi, 10 (SIGUSR1)
    main.extend_from_slice(&[0x48, 0x89, 0xE6]); // mov rsi, rsp
    main.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx (oldact=0)
    main.extend_from_slice(&[0x41, 0xBA, 8, 0, 0, 0]); // mov r10d, 8 (sigsetsize)
    main.extend_from_slice(&[0x0F, 0x05]); // syscall
    main.extend_from_slice(&[0x48, 0x83, 0xC4, 0x40]); // add rsp, 64
    main.extend_from_slice(&[0xB8, 39, 0, 0, 0]); // mov eax, 39 (getpid)
    main.extend_from_slice(&[0x0F, 0x05]); // syscall
    main.extend_from_slice(&[0x89, 0xC7]); // mov edi, eax (pid)
    main.extend_from_slice(&[0xB8, 62, 0, 0, 0]); // mov eax, 62 (kill)
    main.extend_from_slice(&[0xBE, 10, 0, 0, 0]); // mov esi, 10 (SIGUSR1)
    main.extend_from_slice(&[0x0F, 0x05]); // syscall -> delivered on return
    main.extend_from_slice(&[0xB8, 0x44, 0, 0, 0]); // mov eax, 'D'
    main.extend_from_slice(&[0x50]); // push rax
    main.extend_from_slice(&[0xB8, 1, 0, 0, 0]); // mov eax, 1 (write)
    main.extend_from_slice(&[0xBF, 1, 0, 0, 0]); // mov edi, 1
    main.extend_from_slice(&[0x48, 0x89, 0xE6]); // mov rsi, rsp
    main.extend_from_slice(&[0xBA, 1, 0, 0, 0]); // mov edx, 1
    main.extend_from_slice(&[0x0F, 0x05]); // syscall
    main.extend_from_slice(&[0x48, 0x83, 0xC4, 0x08]); // add rsp, 8
    main.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]); // mov eax, 231 (exit_group)
    main.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
    main.extend_from_slice(&[0x0F, 0x05]); // syscall

    let mut code = Vec::new();
    code.extend_from_slice(&handler);
    code.extend_from_slice(&restorer);
    code.extend_from_slice(&main);
    raw_exec_elf_at(&code, entry)
}

/// Builds a program that proves `rt_sigreturn` cannot grant I/O privilege. Its
/// SIGUSR1 handler sets IOPL=3 in the signal frame's saved RFLAGS (uc_mcontext),
/// then after the kernel restores the (sanitised) context it executes
/// `in al, 0x60`. With IOPL left at 0 that faults (#GP -> SIGSEGV); if the
/// sanitiser regressed, the `in` would succeed and the process would exit 0.
fn iopl_sigreturn_elf() -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let headers = 64 + 56u64;

    // handler(sig, info, uc): rdx = &uc. Set IOPL (bits 12-13) in
    // uc.uc_mcontext.eflags (offset 176 in UContext), then return.
    let handler: Vec<u8> = vec![
        0x48, 0x81, 0x8A, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, // or qword [rdx+0xB0],0x3000
        0xC3, // ret
    ];
    let restorer: Vec<u8> = vec![0xB8, 0x0F, 0, 0, 0, 0x0F, 0x05];

    let handler_addr = V + headers;
    let restorer_addr = handler_addr + handler.len() as u64;
    let entry = restorer_addr + restorer.len() as u64;

    let mut main: Vec<u8> = Vec::new();
    main.extend_from_slice(&[0x48, 0x83, 0xEC, 0x40]); // sub rsp, 64
    main.extend_from_slice(&[0x48, 0xB8]);
    main.extend_from_slice(&handler_addr.to_le_bytes()); // movabs rax, handler
    main.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp], rax
    main.extend_from_slice(&[0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x14]); // flags lo = SA_RESTORER|SA_RESTART
    main.extend_from_slice(&[0xC7, 0x44, 0x24, 0x0C, 0x00, 0x00, 0x00, 0x00]); // flags hi = 0
    main.extend_from_slice(&[0x48, 0xB8]);
    main.extend_from_slice(&restorer_addr.to_le_bytes()); // movabs rax, restorer
    main.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x10]); // mov [rsp+16], rax
    main.extend_from_slice(&[0x31, 0xC0]); // xor eax,eax
    main.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+24], rax (mask=0)
    main.extend_from_slice(&[0xB8, 13, 0, 0, 0]); // mov eax,13 (rt_sigaction)
    main.extend_from_slice(&[0xBF, 10, 0, 0, 0]); // mov edi,10 (SIGUSR1)
    main.extend_from_slice(&[0x48, 0x89, 0xE6]); // mov rsi, rsp
    main.extend_from_slice(&[0x31, 0xD2]); // xor edx,edx
    main.extend_from_slice(&[0x41, 0xBA, 8, 0, 0, 0]); // mov r10d,8
    main.extend_from_slice(&[0x0F, 0x05]); // syscall
    main.extend_from_slice(&[0x48, 0x83, 0xC4, 0x40]); // add rsp,64
    main.extend_from_slice(&[0xB8, 39, 0, 0, 0]); // mov eax,39 (getpid)
    main.extend_from_slice(&[0x0F, 0x05]); // syscall
    main.extend_from_slice(&[0x89, 0xC7]); // mov edi,eax
    main.extend_from_slice(&[0xB8, 62, 0, 0, 0]); // mov eax,62 (kill)
    main.extend_from_slice(&[0xBE, 10, 0, 0, 0]); // mov esi,10
    main.extend_from_slice(&[0x0F, 0x05]); // syscall -> handler sets IOPL, sigreturn restores sanitised flags
    main.extend_from_slice(&[0xE4, 0x60]); // in al, 0x60  -> #GP if IOPL<3
    main.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]); // mov eax,231 (exit_group) -- only if NOT faulted
    main.extend_from_slice(&[0x31, 0xFF]); // xor edi,edi
    main.extend_from_slice(&[0x0F, 0x05]); // syscall

    let mut code = Vec::new();
    code.extend_from_slice(&handler);
    code.extend_from_slice(&restorer);
    code.extend_from_slice(&main);
    raw_exec_elf_at(&code, entry)
}

/// Builds a program that proves `fork` is copy-on-write: it writes 'A' to a
/// stack byte, forks, the child overwrites it with 'B' and exits, and the
/// parent (after reaping) checks its own byte is still 'A'. exit 0 = isolated
/// (CoW correct); exit 1 = the child's write leaked into the parent.
fn cow_fork_elf() -> Vec<u8> {
    let code: Vec<u8> = vec![
        0xC6, 0x44, 0x24, 0xF0, 0x41, // mov byte [rsp-16], 'A'
        0xB8, 0x39, 0x00, 0x00, 0x00, // mov eax, 57 (fork)
        0x0F, 0x05, // syscall
        0x48, 0x85, 0xC0, // test rax, rax
        0x74, 0x31, // jz child (+0x31)
        0xB8, 0x3D, 0x00, 0x00, 0x00, // mov eax, 61 (wait4)
        0xBF, 0xFF, 0xFF, 0xFF, 0xFF, // mov edi, -1
        0x31, 0xF6, // xor esi, esi
        0x31, 0xD2, // xor edx, edx
        0x45, 0x31, 0xD2, // xor r10d, r10d
        0x0F, 0x05, // syscall (wait4)
        0x0F, 0xB6, 0x44, 0x24, 0xF0, // movzx eax, byte [rsp-16]
        0x3C, 0x41, // cmp al, 'A'
        0x75, 0x09, // jne fail (+0x09)
        0xB8, 0xE7, 0x00, 0x00, 0x00, // mov eax, 231
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall (exit_group 0)
        0xB8, 0xE7, 0x00, 0x00, 0x00, // (fail:) mov eax, 231
        0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x0F, 0x05, // syscall (exit_group 1)
        0xC6, 0x44, 0x24, 0xF0, 0x42, // (child:) mov byte [rsp-16], 'B'
        0xB8, 0xE7, 0x00, 0x00, 0x00, // mov eax, 231
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall (exit_group 0)
    ];
    raw_exec_elf(&code)
}

/// Builds a program that proves anonymous demand paging: `mmap` 64 KiB, write a
/// byte to a page deep inside (faulted in lazily), read it back, exit 0 iff it
/// round-trips.
fn demand_mmap_elf() -> Vec<u8> {
    let code: Vec<u8> = vec![
        0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9 (mmap)
        0x31, 0xFF, // xor edi, edi
        0xBE, 0x00, 0x00, 0x01, 0x00, // mov esi, 0x10000
        0xBA, 0x03, 0x00, 0x00, 0x00, // mov edx, 3
        0x41, 0xBA, 0x22, 0x00, 0x00, 0x00, // mov r10d, 0x22
        0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov r8d, -1
        0x45, 0x31, 0xC9, // xor r9d, r9d
        0x0F, 0x05, // syscall -> rax=base
        0xC6, 0x80, 0x00, 0x80, 0x00, 0x00, 0x5A, // mov byte [rax+0x8000], 0x5A
        0x0F, 0xB6, 0x88, 0x00, 0x80, 0x00, 0x00, // movzx ecx, byte [rax+0x8000]
        0x80, 0xF9, 0x5A, // cmp cl, 0x5A
        0x75, 0x09, // jne fail (+0x09)
        0xB8, 0xE7, 0x00, 0x00, 0x00, // mov eax, 231
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall (exit_group 0)
        0xB8, 0xE7, 0x00, 0x00, 0x00, // (fail:) mov eax, 231
        0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x0F, 0x05, // syscall (exit_group 1)
    ];
    raw_exec_elf(&code)
}

/// Builds a program that proves clone(CLONE_VM) threads + futex join. It mmaps a
/// child stack, clones a thread (CLONE_VM | CHILD_SETTID | CHILD_CLEARTID with
/// ctid in the shared mapping), the child exits, and the kernel clears the ctid
/// word and futex-wakes it; the parent futex-waits until the word is 0 then
/// exits 0. Exercises clone, a shared address space, thread exit, and futex.
fn clone_thread_elf() -> Vec<u8> {
    let code: Vec<u8> = vec![
        // mmap(0, 0x4000, RW, MAP_PRIVATE|ANON, -1, 0) -> rax = child stack base
        0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9
        0x31, 0xFF, // xor edi, edi
        0xBE, 0x00, 0x40, 0x00, 0x00, // mov esi, 0x4000
        0xBA, 0x03, 0x00, 0x00, 0x00, // mov edx, 3
        0x41, 0xBA, 0x22, 0x00, 0x00, 0x00, // mov r10d, 0x22
        0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov r8d, -1
        0x45, 0x31, 0xC9, // xor r9d, r9d
        0x0F, 0x05, // syscall
        0x49, 0x89, 0xC7, // mov r15, rax  (ctid word lives at [r15])
        0x48, 0x8D, 0xB0, 0x00, 0x40, 0x00, 0x00, // lea rsi, [rax+0x4000] (child sp)
        0xB8, 0x38, 0x00, 0x00, 0x00, // mov eax, 56 (clone)
        0xBF, 0x00, 0x01, 0x20, 0x01, // mov edi, 0x1200100 (VM|CHILD_SETTID|CHILD_CLEARTID)
        0x31, 0xD2, // xor edx, edx (ptid=0)
        0x4D, 0x89, 0xFA, // mov r10, r15 (ctid)
        0x45, 0x31, 0xC0, // xor r8d, r8d (tls=0)
        0x0F, 0x05, // syscall -> rax = child tid (parent) / 0 (child)
        0x48, 0x85, 0xC0, // test rax, rax
        0x74, 0x26, // jz child (+0x26)
        // parent:
        0x41, 0x89, 0xC6, // mov r14d, eax
        // parent_loop:
        0x41, 0x8B, 0x0F, // mov ecx, [r15] (*ctid)
        0x85, 0xC9, // test ecx, ecx
        0x74, 0x13, // jz done (+0x13)
        0xB8, 0xCA, 0x00, 0x00, 0x00, // mov eax, 202 (futex)
        0x4C, 0x89, 0xFF, // mov rdi, r15 (uaddr=ctid)
        0x31, 0xF6, // xor esi, esi (FUTEX_WAIT)
        0x89, 0xCA, // mov edx, ecx (val)
        0x45, 0x31, 0xD2, // xor r10d, r10d (timeout=NULL)
        0x0F, 0x05, // syscall
        0xEB, 0xE6, // jmp parent_loop (-26)
        // done:
        0xB8, 0xE7, 0x00, 0x00, 0x00, // mov eax, 231 (exit_group)
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall
        // child:
        0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall
    ];
    raw_exec_elf(&code)
}

/// Builds a two-segment program whose RO code page and RW data page share one
/// page table (V=0x40_0000 code, V+0x1000 data) — the exact shape that broke
/// CoW: fork maps the RO code leaf first, so the intermediate PML4E/PDPTE/PDE
/// would be created read-only, making the RW data leaf effectively read-only and
/// a child write to it fault forever. Writes 'A' to the data page, forks, the
/// child writes 'B' and exits, the parent checks its byte is still 'A' (exit 0).
fn cow_regression_elf() -> Vec<u8> {
    const V: u64 = 0x40_0000;
    const DATA: u64 = V + 0x1000;
    let headers: u64 = 64 + 56 * 2;
    let d = DATA.to_le_bytes();

    let mut code: Vec<u8> = Vec::new();
    code.push(0x48);
    code.push(0xB8);
    code.extend_from_slice(&d); // movabs rax, DATA
    code.extend_from_slice(&[0xC6, 0x00, 0x41]); // mov byte [rax], 'A'
    code.extend_from_slice(&[0xB8, 0x39, 0, 0, 0]); // mov eax, 57 (fork)
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    code.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    code.extend_from_slice(&[0x74, 0x3A]); // jz child (+0x3A)
    code.extend_from_slice(&[0xB8, 0x3D, 0, 0, 0]); // mov eax, 61 (wait4)
    code.extend_from_slice(&[0xBF, 0xFF, 0xFF, 0xFF, 0xFF]); // mov edi, -1
    code.extend_from_slice(&[0x31, 0xF6]); // xor esi, esi
    code.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx
    code.extend_from_slice(&[0x45, 0x31, 0xD2]); // xor r10d, r10d
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    code.push(0x48);
    code.push(0xB8);
    code.extend_from_slice(&d); // movabs rax, DATA
    code.extend_from_slice(&[0x0F, 0xB6, 0x08]); // movzx ecx, byte [rax]
    code.extend_from_slice(&[0x80, 0xF9, 0x41]); // cmp cl, 'A'
    code.extend_from_slice(&[0x75, 0x09]); // jne fail (+0x09)
    code.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]); // mov eax, 231
    code.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
    code.extend_from_slice(&[0x0F, 0x05]); // syscall (exit 0)
    code.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]); // fail: mov eax, 231
    code.extend_from_slice(&[0xBF, 0x01, 0, 0, 0]); // mov edi, 1
    code.extend_from_slice(&[0x0F, 0x05]); // syscall (exit 1)
    code.push(0x48);
    code.push(0xB8);
    code.extend_from_slice(&d); // child: movabs rax, DATA
    code.extend_from_slice(&[0xC6, 0x00, 0x42]); // mov byte [rax], 'B'
    code.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0]); // mov eax, 231
    code.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
    code.extend_from_slice(&[0x0F, 0x05]); // syscall (exit 0)

    let entry = V + headers;
    let code_filesz = headers + code.len() as u64;

    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]);
    push_u16(&mut elf, 2);
    push_u16(&mut elf, 62);
    push_u32(&mut elf, 1);
    push_u64(&mut elf, entry);
    push_u64(&mut elf, 64);
    push_u64(&mut elf, 0);
    push_u32(&mut elf, 0);
    push_u16(&mut elf, 64);
    push_u16(&mut elf, 56);
    push_u16(&mut elf, 2);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u16(&mut elf, 0);
    push_u32(&mut elf, 1); // PT_LOAD code
    push_u32(&mut elf, 5); // R|X
    push_u64(&mut elf, 0);
    push_u64(&mut elf, V);
    push_u64(&mut elf, V);
    push_u64(&mut elf, code_filesz);
    push_u64(&mut elf, code_filesz);
    push_u64(&mut elf, 0x1000);
    push_u32(&mut elf, 1); // PT_LOAD data
    push_u32(&mut elf, 6); // R|W
    push_u64(&mut elf, 0);
    push_u64(&mut elf, DATA);
    push_u64(&mut elf, DATA);
    push_u64(&mut elf, 0);
    push_u64(&mut elf, 0x1000);
    push_u64(&mut elf, 0x1000);
    elf.extend_from_slice(&code);
    elf
}

/// Builds a program exercising shared-address-space CoW READER coherence: after
/// a fork makes a page CoW, the parent pins itself to CPU 0 and spawns a
/// CLONE_VM reader pinned to CPU 1 (sched_setaffinity) that caches a read-only
/// mapping of the page then spins reading it; after a handshake the main thread
/// writes the page (CoW-copies + shoots down peers). The reader must observe the
/// new value and the join must complete. NOTE: this is a coherence/functional
/// check, not a strict negative guard for the shootdown: this kernel reloads CR3
/// on every context switch, so a preemption flushes a stale entry within one
/// timeslice — a stale reader reads old data only briefly, it never hangs. The
/// shootdown's hard necessity is munmap/free (use-after-free through a stale
/// entry), which the frame-reclamation work will guard directly.
fn clone_cow_reader_elf() -> Vec<u8> {
    // r15 = shared page P (mmap); r14 = reader stack base; join word @[r15+64];
    // "reader cached" handshake flag @[r14+128] (on the stack mapping, demand-
    // paged and NOT CoW, so setting it does not itself copy P).
    let mmap_p: &[u8] = &[
        0xB8, 0x09, 0, 0, 0, 0x31, 0xFF, 0xBE, 0x00, 0x10, 0x00, 0x00, 0xBA, 0x03, 0, 0, 0,
        0x41, 0xBA, 0x22, 0, 0, 0, 0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x31, 0xC9, 0x0F, 0x05,
    ];
    let mmap_s: &[u8] = &[
        0xB8, 0x09, 0, 0, 0, 0x31, 0xFF, 0xBE, 0x00, 0x40, 0x00, 0x00, 0xBA, 0x03, 0, 0, 0,
        0x41, 0xBA, 0x22, 0, 0, 0, 0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x31, 0xC9, 0x0F, 0x05,
    ];
    // sched_setaffinity(0, 8, &mask@[rsp-8]) with the given 1-byte mask.
    let setaffinity = |mask: u8| -> [u8; 25] {
        [
            0xC7, 0x44, 0x24, 0xF8, mask, 0x00, 0x00, 0x00, // mov dword [rsp-8], mask
            0xB8, 0xCB, 0x00, 0x00, 0x00,                   // mov eax, 203
            0x31, 0xFF,                                     // xor edi, edi (pid=0)
            0xBE, 0x08, 0x00, 0x00, 0x00,                   // mov esi, 8 (len)
            0x48, 0x8D, 0x54, 0x24, 0xF8,                   // lea rdx, [rsp-8]
        ]
    };
    let mut c: Vec<u8> = Vec::new();
    c.extend_from_slice(mmap_p);
    c.extend_from_slice(&[0x49, 0x89, 0xC7]); // mov r15, rax
    c.extend_from_slice(mmap_s);
    c.extend_from_slice(&[0x49, 0x89, 0xC6]); // mov r14, rax
    c.extend_from_slice(&[0x41, 0xC6, 0x07, 0x41]); // mov byte [r15], 'A'
    c.extend_from_slice(&[0xB8, 0x39, 0, 0, 0, 0x0F, 0x05]); // fork
    c.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    c.extend_from_slice(&[0x74, 0x00]);
    let jz_fork = c.len() - 1;
    // parent: wait4(-1,0,0,0)
    c.extend_from_slice(&[
        0xB8, 0x3D, 0, 0, 0, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xF6, 0x31, 0xD2, 0x45, 0x31, 0xD2,
        0x0F, 0x05,
    ]);
    c.extend_from_slice(&[0x49, 0x8D, 0xB6, 0x00, 0x40, 0x00, 0x00]); // lea rsi, [r14+0x4000]
    c.extend_from_slice(&[
        0xB8, 0x38, 0, 0, 0, 0xBF, 0x00, 0x01, 0x20, 0x01, 0x31, 0xD2, 0x4D, 0x8D, 0x57, 0x40, 0x45,
        0x31, 0xC0, 0x0F, 0x05,
    ]); // clone(VM|SETTID|CLEARTID, rsi, 0, [r15+64], 0)
    c.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    c.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]);
    let jz_reader = c.len() - 4; // jz reader (rel32)
    // writer (parent-main): pin to CPU0, wait for reader-cached, then write 'B'
    c.extend_from_slice(&setaffinity(0x01)); // CPU 0
    c.extend_from_slice(&[0x0F, 0x05]);       // syscall (setaffinity)
    let wait_cached = c.len();
    c.extend_from_slice(&[0x41, 0x0F, 0xB6, 0x86, 0x80, 0x00, 0x00, 0x00]); // movzx eax, byte [r14+128]
    c.extend_from_slice(&[0x84, 0xC0]); // test al, al
    c.extend_from_slice(&[0x74, 0x00]);
    let jz_waitcached = c.len() - 1; // jz wait_cached (back)
    c.extend_from_slice(&[0x41, 0xC6, 0x07, 0x42]); // mov byte [r15], 'B'  (CoW + shootdown)
    let joinloop = c.len();
    c.extend_from_slice(&[0x41, 0x8B, 0x4F, 0x40]); // mov ecx, [r15+64]
    c.extend_from_slice(&[0x85, 0xC9]); // test ecx, ecx
    c.extend_from_slice(&[0x74, 0x00]);
    let jz_done = c.len() - 1;
    c.extend_from_slice(&[
        0xB8, 0xCA, 0, 0, 0, 0x49, 0x8D, 0x7F, 0x40, 0x31, 0xF6, 0x89, 0xCA, 0x45, 0x31, 0xD2, 0x0F,
        0x05,
    ]); // futex wait on [r15+64]
    c.extend_from_slice(&[0xEB, 0x00]);
    let jmp_join = c.len() - 1;
    let done = c.len();
    c.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0, 0x31, 0xFF, 0x0F, 0x05]); // exit_group 0
    // reader (rel32 target)
    let reader = c.len();
    c.extend_from_slice(&setaffinity(0x02)); // CPU 1 (EINVAL at smp1 -> ignored)
    c.extend_from_slice(&[0x0F, 0x05]);       // syscall
    c.extend_from_slice(&[0x41, 0x0F, 0xB6, 0x07]); // movzx eax, byte [r15]  (cache P RO on CPU1)
    c.extend_from_slice(&[0x41, 0xC6, 0x86, 0x80, 0x00, 0x00, 0x00, 0x01]); // mov byte [r14+128], 1 (signal cached)
    let readloop = c.len();
    c.extend_from_slice(&[0x41, 0x0F, 0xB6, 0x07]); // movzx eax, byte [r15]
    c.extend_from_slice(&[0x3C, 0x41]); // cmp al, 'A'
    c.extend_from_slice(&[0x74, 0x00]);
    let je_read = c.len() - 1; // je readloop (still stale)
    c.extend_from_slice(&[0xB8, 0x3C, 0, 0, 0, 0x31, 0xFF, 0x0F, 0x05]); // exit (thread)
    let forkchild = c.len();
    c.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0, 0x31, 0xFF, 0x0F, 0x05]); // exit_group 0

    // patch rel8 jumps
    let patch8 = |c: &mut Vec<u8>, pos: usize, target: usize| {
        let rel = target as i64 - (pos as i64 + 1);
        c[pos] = (rel as i8) as u8;
    };
    patch8(&mut c, jz_fork, forkchild);
    patch8(&mut c, jz_waitcached, wait_cached);
    patch8(&mut c, jz_done, done);
    patch8(&mut c, jmp_join, joinloop);
    patch8(&mut c, je_read, readloop);
    // patch rel32 (jz reader)
    let rel = reader as i64 - (jz_reader as i64 + 4);
    let rb = (rel as i32).to_le_bytes();
    c[jz_reader] = rb[0];
    c[jz_reader + 1] = rb[1];
    c[jz_reader + 2] = rb[2];
    c[jz_reader + 3] = rb[3];
    raw_exec_elf(&c)
}

/// Builds a program exercising the PTY subsystem end to end: open /dev/ptmx
/// (master), open /dev/pts/0 (slave), write "hi" to the master, read it back
/// from the slave, and verify. Exits 0 on match. (Assumes ptn 0 — it is the
/// first and only PTY opened during the self-tests.)
fn pty_elf() -> Vec<u8> {
    const V: u64 = 0x40_0000;
    let headers: u64 = 64 + 56;
    let base = V + headers;
    // Data laid out first in the segment; code follows.
    let mut data: Vec<u8> = Vec::new();
    let ptmx = base + data.len() as u64;
    data.extend_from_slice(b"/dev/ptmx\0");
    let pts = base + data.len() as u64;
    data.extend_from_slice(b"/dev/pts/0\0");
    let hi = base + data.len() as u64;
    data.extend_from_slice(b"hi");
    let buf = base + data.len() as u64;
    data.extend_from_slice(&[0, 0]);

    let mut c: Vec<u8> = Vec::new();
    // master = open(ptmx, O_RDWR)
    c.extend_from_slice(&[0xB8, 0x02, 0, 0, 0]); // mov eax, 2
    c.extend_from_slice(&[0x48, 0xBF]);
    c.extend_from_slice(&ptmx.to_le_bytes()); // movabs rdi, ptmx
    c.extend_from_slice(&[0xBE, 0x02, 0, 0, 0]); // mov esi, 2 (O_RDWR)
    c.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx
    c.extend_from_slice(&[0x0F, 0x05]); // syscall
    c.extend_from_slice(&[0x49, 0x89, 0xC4]); // mov r12, rax (master)
    // slave = open(pts, O_RDWR)
    c.extend_from_slice(&[0xB8, 0x02, 0, 0, 0]);
    c.extend_from_slice(&[0x48, 0xBF]);
    c.extend_from_slice(&pts.to_le_bytes());
    c.extend_from_slice(&[0xBE, 0x02, 0, 0, 0]);
    c.extend_from_slice(&[0x31, 0xD2]);
    c.extend_from_slice(&[0x0F, 0x05]);
    c.extend_from_slice(&[0x49, 0x89, 0xC5]); // mov r13, rax (slave)
    // write(master, "hi", 2)
    c.extend_from_slice(&[0xB8, 0x01, 0, 0, 0]); // mov eax, 1
    c.extend_from_slice(&[0x44, 0x89, 0xE7]); // mov edi, r12d
    c.extend_from_slice(&[0x48, 0xBE]);
    c.extend_from_slice(&hi.to_le_bytes()); // movabs rsi, hi
    c.extend_from_slice(&[0xBA, 0x02, 0, 0, 0]); // mov edx, 2
    c.extend_from_slice(&[0x0F, 0x05]);
    // read(slave, buf, 2)
    c.extend_from_slice(&[0xB8, 0x00, 0, 0, 0]); // mov eax, 0
    c.extend_from_slice(&[0x44, 0x89, 0xEF]); // mov edi, r13d
    c.extend_from_slice(&[0x48, 0xBE]);
    c.extend_from_slice(&buf.to_le_bytes()); // movabs rsi, buf
    c.extend_from_slice(&[0xBA, 0x02, 0, 0, 0]); // mov edx, 2
    c.extend_from_slice(&[0x0F, 0x05]);
    // verify buf == "hi"
    c.extend_from_slice(&[0x48, 0xB8]);
    c.extend_from_slice(&buf.to_le_bytes()); // movabs rax, buf
    c.extend_from_slice(&[0x0F, 0xB6, 0x08]); // movzx ecx, byte [rax]
    c.extend_from_slice(&[0x80, 0xF9, 0x68]); // cmp cl, 'h'
    c.extend_from_slice(&[0x75, 0x00]);
    let jne1 = c.len() - 1;
    c.extend_from_slice(&[0x0F, 0xB6, 0x48, 0x01]); // movzx ecx, byte [rax+1]
    c.extend_from_slice(&[0x80, 0xF9, 0x69]); // cmp cl, 'i'
    c.extend_from_slice(&[0x75, 0x00]);
    let jne2 = c.len() - 1;
    c.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0, 0x31, 0xFF, 0x0F, 0x05]); // exit_group 0
    let fail = c.len();
    c.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0, 0xBF, 0x01, 0, 0, 0, 0x0F, 0x05]); // exit_group 1

    let patch8 = |c: &mut Vec<u8>, pos: usize, target: usize| {
        c[pos] = ((target as i64 - (pos as i64 + 1)) as i8) as u8;
    };
    patch8(&mut c, jne1, fail);
    patch8(&mut c, jne2, fail);

    let mut seg = data;
    let entry = base + seg.len() as u64;
    seg.extend_from_slice(&c);
    raw_exec_elf_at(&seg, entry)
}

/// Builds a program that proves the pipe primitive end to end: pipe2(), fork,
/// the child writes "PX" to the write end, the parent reads it from the read
/// end and verifies, then reaps the child. Exits 0 on match. This validates
/// pipes independently of busybox/the shell e2e (and its timing).
fn pipe_selftest_elf() -> Vec<u8> {
    // r12d = read fd, r13d = write fd; scratch buffers on the stack.
    let mut c: Vec<u8> = Vec::new();
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 32
    c.extend_from_slice(&[0xB8, 0x25, 0x01, 0x00, 0x00]); // mov eax, 293 (pipe2)
    c.extend_from_slice(&[0x48, 0x89, 0xE7]); // mov rdi, rsp
    c.extend_from_slice(&[0x31, 0xF6]); // xor esi, esi
    c.extend_from_slice(&[0x0F, 0x05]); // syscall
    c.extend_from_slice(&[0x44, 0x8B, 0x24, 0x24]); // mov r12d, [rsp]
    c.extend_from_slice(&[0x44, 0x8B, 0x6C, 0x24, 0x04]); // mov r13d, [rsp+4]
    c.extend_from_slice(&[0xB8, 0x39, 0, 0, 0, 0x0F, 0x05]); // fork
    c.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    c.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // jz child (rel32)
    let jz_child = c.len() - 4;
    // --- parent ---
    // close(write end) so only the child holds a writer
    c.extend_from_slice(&[0xB8, 0x03, 0, 0, 0, 0x44, 0x89, 0xEF, 0x0F, 0x05]); // mov eax,3; mov edi,r13d; syscall (close)
    // n1 = read(read fd, [rsp+8], 8)  -> expect 2 bytes "PX"
    c.extend_from_slice(&[0xB8, 0x00, 0, 0, 0]); // mov eax, 0
    c.extend_from_slice(&[0x44, 0x89, 0xE7]); // mov edi, r12d
    c.extend_from_slice(&[0x48, 0x8D, 0x74, 0x24, 0x08]); // lea rsi, [rsp+8]
    c.extend_from_slice(&[0xBA, 0x08, 0, 0, 0]); // mov edx, 8
    c.extend_from_slice(&[0x0F, 0x05]); // syscall
    c.extend_from_slice(&[0x48, 0x83, 0xF8, 0x02]); // cmp rax, 2
    c.extend_from_slice(&[0x75, 0x00]); let jne_n1 = c.len() - 1; // jne fail
    c.extend_from_slice(&[0x0F, 0xB6, 0x4C, 0x24, 0x08]); // movzx ecx, byte [rsp+8]
    c.extend_from_slice(&[0x80, 0xF9, 0x50]); // cmp cl, 'P'
    c.extend_from_slice(&[0x75, 0x00]); let jne_p = c.len() - 1;
    c.extend_from_slice(&[0x0F, 0xB6, 0x4C, 0x24, 0x09]); // movzx ecx, byte [rsp+9]
    c.extend_from_slice(&[0x80, 0xF9, 0x58]); // cmp cl, 'X'
    c.extend_from_slice(&[0x75, 0x00]); let jne_x = c.len() - 1;
    // n2 = read(read fd, [rsp+16], 8) -> expect 0 (EOF: all writers closed)
    c.extend_from_slice(&[0xB8, 0x00, 0, 0, 0]);
    c.extend_from_slice(&[0x44, 0x89, 0xE7]);
    c.extend_from_slice(&[0x48, 0x8D, 0x74, 0x24, 0x10]); // lea rsi, [rsp+16]
    c.extend_from_slice(&[0xBA, 0x08, 0, 0, 0]);
    c.extend_from_slice(&[0x0F, 0x05]);
    c.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    c.extend_from_slice(&[0x75, 0x00]); let jnz_eof = c.len() - 1; // jnz fail (n2 != 0)
    // wait4(-1,0,0,0)
    c.extend_from_slice(&[0xB8, 0x3D, 0, 0, 0, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xF6, 0x31, 0xD2, 0x45, 0x31, 0xD2, 0x0F, 0x05]);
    c.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0, 0x31, 0xFF, 0x0F, 0x05]); // exit_group 0
    let fail = c.len();
    c.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0, 0xBF, 0x01, 0, 0, 0, 0x0F, 0x05]); // exit_group 1
    let child = c.len();
    // --- child ---
    c.extend_from_slice(&[0xB8, 0x03, 0, 0, 0, 0x44, 0x89, 0xE7, 0x0F, 0x05]); // close(read fd): mov eax,3; mov edi,r12d; syscall
    c.extend_from_slice(&[0x66, 0xC7, 0x44, 0x24, 0x18, 0x50, 0x58]); // mov word [rsp+24], 0x5850 ("PX")
    c.extend_from_slice(&[0xB8, 0x01, 0, 0, 0]); // mov eax, 1 (write)
    c.extend_from_slice(&[0x44, 0x89, 0xEF]); // mov edi, r13d
    c.extend_from_slice(&[0x48, 0x8D, 0x74, 0x24, 0x18]); // lea rsi, [rsp+24]
    c.extend_from_slice(&[0xBA, 0x02, 0, 0, 0]); // mov edx, 2
    c.extend_from_slice(&[0x0F, 0x05]);
    c.extend_from_slice(&[0xB8, 0xE7, 0, 0, 0, 0x31, 0xFF, 0x0F, 0x05]); // exit_group 0 (closes child's write end -> parent EOF)

    let patch8 = |c: &mut Vec<u8>, pos: usize, target: usize| {
        let rel = target as i64 - (pos as i64 + 1);
        assert!((-128..=127).contains(&rel));
        c[pos] = (rel as i8) as u8;
    };
    for &pos in &[jne_n1, jne_p, jne_x, jnz_eof] {
        patch8(&mut c, pos, fail);
    }
    let rel = child as i64 - (jz_child as i64 + 4);
    let rb = (rel as i32).to_le_bytes();
    c[jz_child..jz_child + 4].copy_from_slice(&rb);
    raw_exec_elf(&c)
}

/// Reclamation observability: spawns a batch of tiny processes, waits for each
/// to exit, reaps it, and logs the free-frame count before and after. With leaf
/// reclamation working the two counts are close (only a few page-table frames
/// per process leak, pending the teardown/CR3-eviction step); a large drop would
/// indicate leaf frames are leaking.
pub fn run_reclaim_selftest() {
    let (before, _) = crate::mm::phys::stats();
    for _ in 0..4 {
        if let Ok(proc) = spawn(&hello_elf(), &["/r"], &["PATH=/bin"]) {
            let _ = await_exit(&proc, "reclaim");
        }
        crate::process::reap_orphan_zombies();
    }
    let (after, _) = crate::mm::phys::stats();
    crate::log::info!(
        "reclaim selftest: free frames {before} -> {after} after 4 spawn+exit+reap (leaf frames reclaimed; page-table frames leak until teardown lands)"
    );
}

/// Runs the memory-management self-tests (CoW fork, anonymous demand paging).
/// Each must exit 0; anything else indicates a VM correctness bug.
pub fn run_vm_selftests() {
    // Order matters: the clone test runs first so ADDRESS_SPACE_SHARED is set,
    // making the subsequent CoW faults exercise the shared-space TLB shootdown
    // (cross-CPU at smp > 1).
    for (name, image) in [
        ("clone(CLONE_VM) thread + futex join", clone_thread_elf()),
        ("cow fork isolation", cow_fork_elf()),
        ("anon demand paging", demand_mmap_elf()),
        ("cow RO-code + RW-data same PT (shared-space shootdown)", cow_regression_elf()),
        ("clone(CLONE_VM) reader sees CoW write (shootdown)", clone_cow_reader_elf()),
        ("pty: master<->slave via /dev/ptmx + /dev/pts/0", pty_elf()),
        ("pipe2 + fork read/write + EOF", pipe_selftest_elf()),
    ] {
        match spawn(&image, &["/vm-test"], &[]) {
            Ok(proc) => {
                let code = await_exit(&proc, name);
                if code == 0 {
                    crate::log::info!("vm selftest [{name}]: OK");
                } else {
                    crate::log::error!("vm selftest [{name}]: FAILED (exit {code})");
                }
            }
            Err(e) => crate::log::error!("vm selftest [{name}]: spawn failed: {e:?}"),
        }
    }
}

/// Runs the signal self-test: a program that catches SIGUSR1, raises it on
/// itself, and resumes after the handler. The kernel must set up and tear down
/// the signal frame correctly; a clean exit (status 0) proves the round trip.
pub fn run_signal_selftest() {
    let image = signal_handler_elf();
    match spawn(&image, &["/sig-test"], &[]) {
        Ok(proc) => {
            let code = await_exit(&proc, "signal");
            if code == 0 {
                crate::log::info!(
                    "signal selftest: SIGUSR1 handler ran and rt_sigreturn resumed cleanly (exit 0)"
                );
            } else {
                crate::log::error!("signal selftest: unexpected exit status {code}");
            }
        }
        Err(e) => crate::log::error!("signal selftest: spawn failed: {e:?}"),
    }
}

/// Dumps every CPU's current thread (id/state) for diagnosing a stuck self-test.
/// A running process that never exits is almost always a lost wakeup or a lock
/// held across a block; this converts an otherwise silent hang into a panic with
/// a backtrace and this per-CPU snapshot.
fn watchdog_dump(name: &str) {
    crate::log::error!("WATCHDOG: self-test '{name}' did not finish in time; per-CPU state:");
    let n = crate::percpu::count();
    for id in 0..n {
        if let Some(cpu) = crate::percpu::by_id(id) {
            let cur = cpu.current.load(core::sync::atomic::Ordering::Acquire);
            let (tid, ltid, state) = if cur.is_null() {
                (0, 0, crate::thread::State::Finished)
            } else {
                // SAFETY: `cur` is this CPU's live current thread pointer.
                unsafe { ((*cur).tid(), (*cur).linux_tid, (*cur).state) }
            };
            let preempt = cpu.preempt_count.load(core::sync::atomic::Ordering::Relaxed);
            crate::log::error!(
                "  cpu{id}: current tid={tid:#x} linux_tid={ltid} state={state:?} preempt_count={preempt}"
            );
        }
    }
}

/// Waits for `proc` to exit, returning its status. A TSC-based watchdog turns a
/// stuck self-test into a diagnostic dump + panic instead of an indefinite spin.
fn await_exit(proc: &Arc<SpinLock<Process>>, name: &str) -> i32 {
    // SAFETY: `_rdtsc` reads the timestamp counter.
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    // Generous ceiling (~tens of seconds under TCG); only ever hit by a real hang.
    const WATCHDOG_CYCLES: u64 = 120_000_000_000;
    loop {
        if let Some(c) = proc.lock().exit_code {
            return c;
        }
        scheduler::yield_now();
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) > WATCHDOG_CYCLES {
            watchdog_dump(name);
            panic!("self-test watchdog: '{name}' never finished");
        }
    }
}

/// Runs the ring-3 security self-tests. Each spawns a hostile user program that/// Runs the ring-3 security self-tests. Each spawns a hostile user program that
/// must be *contained to its own process* — killed by a signal (bad instruction
/// / bad memory access) or have its offending syscall rejected — without ever
/// panicking or wedging the kernel. Every case must reach an exit status, and
/// the kernel must keep running afterwards (the final "kernel alive" line and a
/// clean boot are the proof).
pub fn run_security_selftests() {
    // Each case names the hostile program, its ELF, and the EXACT exit status
    // that proves containment (128 + signal for a signal kill, 0 for a rejected
    // syscall). Checking the status — not merely "exited" — is what makes the
    // IOPL case meaningful: exiting 0 there would mean the escalation succeeded.
    let cases: [(&str, Vec<u8>, i32); 5] = [
        ("ud2 (#UD -> SIGILL)", ud2_elf(), 128 + abi::types::SIGILL),
        ("store to unmapped (#PF -> SIGSEGV)", bad_store_elf(), 128 + abi::types::SIGSEGV),
        ("write(1, buf, 1<<40) (bounded)", huge_write_elf(), 0),
        ("arch_prctl(SET_FS, non-canonical) (EINVAL)", bad_setfs_elf(), 0),
        ("rt_sigreturn IOPL=3 then in al,0x60 (#GP -> SIGSEGV)", iopl_sigreturn_elf(), 128 + abi::types::SIGSEGV),
    ];
    let total = cases.len();
    let mut passed = 0usize;
    for (name, image, expected) in cases {
        match spawn(&image, &["/sec-test"], &[]) {
            Ok(proc) => {
                let code = await_exit(&proc, name);
                if code == expected {
                    crate::log::info!("security selftest [{name}]: contained, exit status {code}");
                    passed += 1;
                } else {
                    crate::log::error!(
                        "security selftest [{name}]: FAILED -- exit status {code}, expected {expected}"
                    );
                }
            }
            Err(e) => crate::log::error!("security selftest [{name}]: spawn failed: {e:?}"),
        }
    }
    crate::log::info!("security selftests: {passed}/{total} processes contained; kernel alive");
    crate::process::reap_orphan_zombies();
}

/// Measures getpid round-trip latency by running a tight getpid loop in user
/// mode and reading the kernel-side measurement.
pub fn run_syscall_bench() {
    const N: u32 = 200_000;
    crate::syscall::bench_arm(u64::from(N));
    let elf_image = getpid_loop_elf(N);
    match spawn(&elf_image, &["/bench"], &[]) {
        Ok(proc) => {
            let mut spins = 0u64;
            while proc.lock().exit_code.is_none() {
                scheduler::yield_now();
                spins += 1;
                if spins > 200_000_000 {
                    crate::log::error!("syscall bench: timed out");
                    return;
                }
            }
            crate::log::info!(
                "syscall latency: ~{} cycles per getpid round-trip ({} calls)",
                crate::syscall::bench_result(),
                N,
            );
        }
        Err(e) => crate::log::error!("syscall bench: spawn failed: {e:?}"),
    }
}

/// Runs the userspace self-test: load the hello ELF, run it to completion, and
/// report its exit status.
pub fn run_selftest() {
    let elf_image = hello_elf();
    match spawn(&elf_image, &["/init"], &["PATH=/bin", "HOME=/", "TERM=xterm-256color"]) {
        Ok(proc) => {
            let mut spins = 0u64;
            loop {
                if proc.lock().exit_code.is_some() {
                    break;
                }
                scheduler::yield_now();
                spins += 1;
                if spins > 50_000_000 {
                    crate::log::error!("userspace selftest: timed out");
                    return;
                }
            }
            let code = proc.lock().exit_code;
            crate::log::info!("userspace selftest: hello process exited with {code:?}");
        }
        Err(e) => crate::log::error!("userspace selftest: spawn failed: {e:?}"),
    }
}

/// Loads `/bin/busybox` from the initramfs and runs it as the interactive shell
/// (`argv[0] = "/bin/sh"`). The calling (bootstrap) thread then yields forever,
/// letting the scheduler run the shell. Only reached on a real boot.
pub fn run_init() {
    // Preferred login shell first, then fallbacks. argv[0] starting with '-'
    // makes it a login shell (reads /etc/zprofile, ~/.zprofile, ~/.zshrc).
    const CANDIDATES: &[(&str, &str)] = &[
        ("/usr/bin/zsh", "-zsh"),
        ("/bin/sh", "-sh"),
        ("/bin/busybox", "sh"),
    ];
    const UID: u32 = 1000;
    const GID: u32 = 1000;
    let envp = &[
        "HOME=/home/rodolfo",
        "USER=rodolfo",
        "LOGNAME=rodolfo",
        "SHELL=/usr/bin/zsh",
        "TERM=xterm-256color",
        "PATH=/usr/bin:/usr/local/bin:/bin",
        "PWD=/home/rodolfo",
    ];

    for (path, arg0) in CANDIDATES {
        let image = match crate::fs::read_file(path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        crate::log::info!("init: starting {path} ({} KiB) as login shell", image.len() / 1024);
        // busybox fallback needs an explicit -i (its arg0 convention differs);
        // zsh/sh take a leading-'-' arg0 for a login shell.
        // `zshrc=none` on the kernel cmdline launches the shell with `-f` (skip
        // all rc files/plugins) — a debug knob to isolate a hung plugin/zinit
        // config from a kernel bug.
        let norc = crate::boot::cmdline().split_ascii_whitespace().any(|t| t == "zshrc=none");
        let argv: &[&str] = if *path == "/bin/busybox" {
            &["/bin/busybox", "sh", "-i"]
        } else if norc {
            &[arg0, "-l", "-f"]
        } else {
            &[arg0, "-l"]
        };
        match spawn_as(&image, argv, envp, UID, GID) {
            Ok(proc) => {
                // The shell is the session/foreground group leader on the console
                // (its controlling terminal), so Ctrl-C/Ctrl-Z reach its jobs.
                let pgid = {
                    let mut g = proc.lock();
                    // Kernel-spawned (no execve), so set comm for logs/strace here.
                    g.comm = path.rsplit('/').next().unwrap_or(path).into();
                    g.pgid
                };
                crate::fs::set_foreground_pgrp(pgid);
                crate::log::info!("init: {path} started (foreground pgrp {pgid}, uid {UID})");
                // Act as init: reap orphaned zombies (reclaiming their frames).
                loop {
                    scheduler::yield_now();
                    crate::process::reap_orphan_zombies();
                }
            }
            Err(e) => crate::log::error!("init: failed to start {path}: {e:?}"),
        }
    }
    crate::log::error!("init: no login shell found (tried zsh, sh, busybox)");
}
