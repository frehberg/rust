use crate::fmt;
use crate::io::{self, Error, ErrorKind};
use crate::ptr;
use crate::sys::cvt;
use crate::sys::process::process_common::*;
use crate::sys;
use crate::sys::unix::pipe::AnonPipe;
use crate::sys::unix::fd::FileDesc;

use libc::{c_int, gid_t, pid_t, uid_t};

////////////////////////////////////////////////////////////////////////////////
// Command
////////////////////////////////////////////////////////////////////////////////

impl Command {
    pub fn spawn(&mut self, default: Stdio, needs_stdin: bool)
                 -> io::Result<(Process, StdioPipes)> {
        use crate::sys::{self, cvt_r};

        const CLOEXEC_MSG_FOOTER: &[u8] = b"NOEX";

        let envp = self.capture_env();

        if self.saw_nul() {
            return Err(io::Error::new(ErrorKind::InvalidInput,
                                      "nul byte found in provided data"));
        }

        let (ours, theirs) = self.setup_io(default, needs_stdin)?;

        let (input, output) = sys::pipe::anon_pipe()?;
        let (death_rx, death_tx) = sys::pipe::anon_pipe()?;

        // Whatever happens after the fork is almost for sure going to touch or
        // look at the environment in one way or another (PATH in `execvp` or
        // accessing the `environ` pointer ourselves). Make sure no other thread
        // is accessing the environment when we do the fork itself.
        //
        // Note that as soon as we're done with the fork there's no need to hold
        // a lock any more because the parent won't do anything and the child is
        // in its own process.
        let result = unsafe {
            let _env_lock = sys::os::env_lock();
            cvt(libc::fork())?
        };

        let pid = unsafe {
            match result {
                0 => {
                    drop(input);
                    // close death_rx and inherit death_tx to sub-process
                    drop(death_rx);
                    // the anonpipe has been created with CLOEXEC, and would be closed when execve is
                    // invoked. Therefor we place a duplicate into the process context,
                    // without CLOEXEC-flag. This fd will 'leak' into the child-process, occupying a
                    // file-descriptor slot.
                    let _death_tx = cvt_r(|| libc::dup(death_tx.fd().raw()))?;

                    let Err(err) = self.do_exec(theirs, envp.as_ref());
                    let errno = err.raw_os_error().unwrap_or(libc::EINVAL) as u32;
                    let bytes = [
                        (errno >> 24) as u8,
                        (errno >> 16) as u8,
                        (errno >>  8) as u8,
                        (errno >>  0) as u8,
                        CLOEXEC_MSG_FOOTER[0], CLOEXEC_MSG_FOOTER[1],
                        CLOEXEC_MSG_FOOTER[2], CLOEXEC_MSG_FOOTER[3]
                    ];
                    // pipe I/O up to PIPE_BUF bytes should be atomic, and then
                    // we want to be sure we *don't* run at_exit destructors as
                    // we're being torn down regardless
                    assert!(output.write(&bytes).is_ok());
                    libc::_exit(1)
                }
                n => n,
            }
        };

        let mut p = Process { pid: pid, status: None, death_rx: death_rx };
        drop(output);
        let mut bytes = [0; 8];

        // loop to handle EINTR
        loop {
            match input.read(&mut bytes) {
                Ok(0) => return Ok((p, ours)),
                Ok(8) => {
                    assert!(combine(CLOEXEC_MSG_FOOTER) == combine(&bytes[4.. 8]),
                            "Validation on the CLOEXEC pipe failed: {:?}", bytes);
                    let errno = combine(&bytes[0.. 4]);
                    assert!(p.wait().is_ok(),
                            "wait() should either return Ok or panic");
                    return Err(Error::from_raw_os_error(errno))
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    assert!(p.wait().is_ok(),
                            "wait() should either return Ok or panic");
                    panic!("the CLOEXEC pipe failed: {:?}", e)
                },
                Ok(..) => { // pipe I/O up to PIPE_BUF bytes should be atomic
                    assert!(p.wait().is_ok(),
                            "wait() should either return Ok or panic");
                    panic!("short read on the CLOEXEC pipe")
                }
            }
        }

        fn combine(arr: &[u8]) -> i32 {
            let a = arr[0] as u32;
            let b = arr[1] as u32;
            let c = arr[2] as u32;
            let d = arr[3] as u32;

            ((a << 24) | (b << 16) | (c << 8) | (d << 0)) as i32
        }
    }

    pub fn exec(&mut self, default: Stdio) -> io::Error {
        let envp = self.capture_env();

        if self.saw_nul() {
            return io::Error::new(ErrorKind::InvalidInput,
                                  "nul byte found in provided data")
        }

        match self.setup_io(default, true) {
            Ok((_, theirs)) => {
                unsafe {
                    // Similar to when forking, we want to ensure that access to
                    // the environment is synchronized, so make sure to grab the
                    // environment lock before we try to exec.
                    let _lock = sys::os::env_lock();

                    let Err(e) = self.do_exec(theirs, envp.as_ref());
                    e
                }
            }
            Err(e) => e,
        }
    }

    // And at this point we've reached a special time in the life of the
    // child. The child must now be considered hamstrung and unable to
    // do anything other than syscalls really. Consider the following
    // scenario:
    //
    //      1. Thread A of process 1 grabs the malloc() mutex
    //      2. Thread B of process 1 forks(), creating thread C
    //      3. Thread C of process 2 then attempts to malloc()
    //      4. The memory of process 2 is the same as the memory of
    //         process 1, so the mutex is locked.
    //
    // This situation looks a lot like deadlock, right? It turns out
    // that this is what pthread_atfork() takes care of, which is
    // presumably implemented across platforms. The first thing that
    // threads to *before* forking is to do things like grab the malloc
    // mutex, and then after the fork they unlock it.
    //
    // Despite this information, libnative's spawn has been witnessed to
    // deadlock on both macOS and FreeBSD. I'm not entirely sure why, but
    // all collected backtraces point at malloc/free traffic in the
    // child spawned process.
    //
    // For this reason, the block of code below should contain 0
    // invocations of either malloc of free (or their related friends).
    //
    // As an example of not having malloc/free traffic, we don't close
    // this file descriptor by dropping the FileDesc (which contains an
    // allocation). Instead we just close it manually. This will never
    // have the drop glue anyway because this code never returns (the
    // child will either exec() or invoke libc::exit)
    unsafe fn do_exec(
        &mut self,
        stdio: ChildPipes,
        maybe_envp: Option<&CStringArray>
    ) -> Result<!, io::Error> {
        use crate::sys::{self, cvt_r};

        if let Some(fd) = stdio.stdin.fd() {
            cvt_r(|| libc::dup2(fd, libc::STDIN_FILENO))?;
        }
        if let Some(fd) = stdio.stdout.fd() {
            cvt_r(|| libc::dup2(fd, libc::STDOUT_FILENO))?;
        }
        if let Some(fd) = stdio.stderr.fd() {
            cvt_r(|| libc::dup2(fd, libc::STDERR_FILENO))?;
        }

        #[cfg(not(target_os = "l4re"))]
        {
            if let Some(u) = self.get_gid() {
                cvt(libc::setgid(u as gid_t))?;
            }
            if let Some(u) = self.get_uid() {
                // When dropping privileges from root, the `setgroups` call
                // will remove any extraneous groups. If we don't call this,
                // then even though our uid has dropped, we may still have
                // groups that enable us to do super-user things. This will
                // fail if we aren't root, so don't bother checking the
                // return value, this is just done as an optimistic
                // privilege dropping function.
                //FIXME: Redox kernel does not support setgroups yet
                #[cfg(not(target_os = "redox"))]
                let _ = libc::setgroups(0, ptr::null());
                cvt(libc::setuid(u as uid_t))?;
            }
        }
        if let Some(ref cwd) = *self.get_cwd() {
            cvt(libc::chdir(cwd.as_ptr()))?;
        }

        // emscripten has no signal support.
        #[cfg(not(target_os = "emscripten"))]
        {
            use crate::mem::MaybeUninit;
            // Reset signal handling so the child process starts in a
            // standardized state. libstd ignores SIGPIPE, and signal-handling
            // libraries often set a mask. Child processes inherit ignored
            // signals and the signal mask from their parent, but most
            // UNIX programs do not reset these things on their own, so we
            // need to clean things up now to avoid confusing the program
            // we're about to run.
            let mut set = MaybeUninit::<libc::sigset_t>::uninit();
            cvt(sigemptyset(set.as_mut_ptr()))?;
            cvt(libc::pthread_sigmask(libc::SIG_SETMASK, set.as_ptr(),
                                         ptr::null_mut()))?;
            let ret = sys::signal(libc::SIGPIPE, libc::SIG_DFL);
            if ret == libc::SIG_ERR {
                return Err(io::Error::last_os_error())
            }
        }

        for callback in self.get_closures().iter_mut() {
            callback()?;
        }

        // Although we're performing an exec here we may also return with an
        // error from this function (without actually exec'ing) in which case we
        // want to be sure to restore the global environment back to what it
        // once was, ensuring that our temporary override, when free'd, doesn't
        // corrupt our process's environment.
        let mut _reset = None;
        if let Some(envp) = maybe_envp {
            struct Reset(*const *const libc::c_char);

            impl Drop for Reset {
                fn drop(&mut self) {
                    unsafe {
                        *sys::os::environ() = self.0;
                    }
                }
            }

            _reset = Some(Reset(*sys::os::environ()));
            *sys::os::environ() = envp.as_ptr();
        }

        libc::execvp(self.get_argv()[0], self.get_argv().as_ptr());
        Err(io::Error::last_os_error())
    }

}

////////////////////////////////////////////////////////////////////////////////
// Processes
////////////////////////////////////////////////////////////////////////////////

/// The unique ID of the process (this should never be negative).
pub struct Process {
    pid: pid_t,
    status: Option<ExitStatus>,
    death_rx: AnonPipe,
}

impl Process {
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn kill(&mut self) -> io::Result<()> {
        // If we've already waited on this process then the pid can be recycled
        // and used for another process, and we probably shouldn't be killing
        // random processes, so just return an error.
        if self.status.is_some() {
            Err(Error::new(ErrorKind::InvalidInput,
                           "invalid argument: can't kill an exited process"))
        } else {
            cvt(unsafe { libc::kill(self.pid, libc::SIGKILL) }).map(|_| ())
        }
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        use crate::sys::cvt_r;
        if let Some(status) = self.status {
            return Ok(status)
        }
        let mut status = 0 as c_int;
        cvt_r(|| unsafe { libc::waitpid(self.pid, &mut status, 0) })?;
        self.status = Some(ExitStatus::new(status));
        Ok(ExitStatus::new(status))
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status))
        }
        let mut status = 0 as c_int;
        let pid = cvt(unsafe {
            libc::waitpid(self.pid, &mut status, libc::WNOHANG)
        })?;
        if pid == 0 {
            Ok(None)
        } else {
            self.status = Some(ExitStatus::new(status));
            Ok(Some(ExitStatus::new(status)))
        }
    }

    pub fn handle(&self) ->  &FileDesc { &self.death_rx.fd() }
}

/// Unix exit statuses
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExitStatus(c_int);

impl ExitStatus {
    pub fn new(status: c_int) -> ExitStatus {
        ExitStatus(status)
    }

    fn exited(&self) -> bool {
        unsafe { libc::WIFEXITED(self.0) }
    }

    pub fn success(&self) -> bool {
        self.code() == Some(0)
    }

    pub fn code(&self) -> Option<i32> {
        if self.exited() {
            Some(unsafe { libc::WEXITSTATUS(self.0) })
        } else {
            None
        }
    }

    pub fn signal(&self) -> Option<i32> {
        if !self.exited() {
            Some(unsafe { libc::WTERMSIG(self.0) })
        } else {
            None
        }
    }
}

impl From<c_int> for ExitStatus {
    fn from(a: c_int) -> ExitStatus {
        ExitStatus(a)
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code() {
            write!(f, "exit code: {}", code)
        } else {
            let signal = self.signal().unwrap();
            write!(f, "signal: {}", signal)
        }
    }
}
