/*
Badly coded by @ApkUnpacker 
Inspired From Interruptor and this is nothing compare to what interruptor can do
Recommended to use Interruptor
https://t.me/dexcalibur
@dexcalibur
*/
var ourlib = 'libName.so';
if (Process.arch == "arm64") {
    var do_dlopen = null;
    var call_ctor = null;
    var SyscallNumber = {
        0: 'io_setup',
        1: 'io_destroy',
        2: 'io_submit',
        3: 'io_cancel',
        4: 'io_getevents',
        5: 'setxattr',
        6: 'lsetxattr',
        7: 'fsetxattr',
        8: 'getxattr',
        9: 'lgetxattr',
        10: 'fgetxattr',
        11: 'listxattr',
        12: 'llistxattr',
        13: 'flistxattr',
        14: 'removexattr',
        15: 'lremovexattr',
        16: 'fremovexattr',
        17: 'getcwd',
        18: 'lookup_dcookie',
        19: 'eventfd2',
        20: 'epoll_create1',
        21: 'epoll_ctl',
        22: 'epoll_pwait',
        23: 'dup',
        24: 'dup3',
        25: 'fcntl',
        26: 'inotify_init1',
        27: 'inotify_add_watch',
        28: 'inotify_rm_watch',
        29: 'ioctl',
        30: 'ioprio_set',
        31: 'ioprio_get',
        32: 'flock',
        33: 'mknodat',
        34: 'mkdirat',
        35: 'unlinkat',
        36: 'symlinkat',
        37: 'linkat',
        38: 'renameat',
        39: 'umount2',
        40: 'mount',
        41: 'pivot_root',
        42: 'nfsservctl',
        43: 'statfs',
        44: 'fstatfs',
        45: 'truncate',
        46: 'ftruncate',
        47: 'fallocate',
        48: 'faccessat',
        49: 'chdir',
        50: 'fchdir',
        51: 'chroot',
        52: 'fchmod',
        53: 'fchmodat',
        54: 'fchownat',
        55: 'fchown',
        56: 'openat',
        57: 'close',
        58: 'vhangup',
        59: 'pipe2',
        60: 'quotactl',
        61: 'getdents64',
        62: 'lseek',
        63: 'read',
        64: 'write',
        65: 'readv',
        66: 'writev',
        67: 'pread64',
        68: 'pwrite64',
        69: 'preadv',
        70: 'pwritev',
        71: 'sendfile',
        72: 'pselect6',
        73: 'ppoll',
        74: 'signalfd4',
        75: 'vmsplice',
        76: 'splice',
        77: 'tee',
        78: 'readlinkat',
        79: 'fstatat',
        80: 'fstat',
        81: 'sync',
        82: 'fsync',
        83: 'fdatasync',
        84: 'sync_file_range',
        85: 'timerfd_create',
        86: 'timerfd_settime',
        87: 'timerfd_gettime',
        88: 'utimensat',
        89: 'acct',
        90: 'capget',
        91: 'capset',
        92: 'personality',
        93: 'exit',
        94: 'exit_group',
        95: 'waitid',
        96: 'set_tid_address',
        97: 'unshare',
        98: 'futex',
        99: 'set_robust_list',
        100: 'get_robust_list',
        101: 'nanosleep',
        102: 'getitimer',
        103: 'setitimer',
        104: 'kexec_load',
        105: 'init_module',
        106: 'delete_module',
        107: 'timer_create',
        108: 'timer_gettime',
        109: 'timer_getoverrun',
        110: 'timer_settime',
        111: 'timer_delete',
        112: 'clock_settime',
        113: 'clock_gettime',
        114: 'clock_getres',
        115: 'clock_nanosleep',
        116: 'syslog',
        117: 'ptrace',
        118: 'sched_setparam',
        119: 'sched_setscheduler',
        120: 'sched_getscheduler',
        121: 'sched_getparam',
        122: 'sched_setaffinity',
        123: 'sched_getaffinity',
        124: 'sched_yield',
        125: 'sched_get_priority_max',
        126: 'sched_get_priority_min',
        127: 'sched_rr_get_interval',
        128: 'restart_syscall',
        129: 'kill',
        130: 'tkill',
        131: 'tgkill',
        132: 'sigaltstack',
        133: 'rt_sigsuspend',
        134: 'rt_sigaction',
        135: 'rt_sigprocmask',
        136: 'rt_sigpending',
        137: 'rt_sigtimedwait',
        138: 'rt_sigqueueinfo',
        139: 'rt_sigreturn',
        140: 'setpriority',
        141: 'getpriority',
        142: 'reboot',
        143: 'setregid',
        144: 'setgid',
        145: 'setreuid',
        146: 'setuid',
        147: 'setresuid',
        148: 'getresuid',
        149: 'setresgid',
        150: 'getresgid',
        151: 'setfsuid',
        152: 'setfsgid',
        153: 'times',
        154: 'setpgid',
        155: 'getpgid',
        156: 'getsid',
        157: 'setsid',
        158: 'getgroups',
        159: 'setgroups',
        160: 'uname',
        161: 'sethostname',
        162: 'setdomainname',
        163: 'getrlimit',
        164: 'setrlimit',
        165: 'getrusage',
        166: 'umask',
        167: 'prctl',
        168: 'getcpu',
        169: 'gettimeofday',
        170: 'settimeofday',
        171: 'adjtimex',
        172: 'getpid',
        173: 'getppid',
        174: 'getuid',
        175: 'geteuid',
        176: 'getgid',
        177: 'getegid',
        178: 'gettid',
        179: 'sysinfo',
        180: 'mq_open',
        181: 'mq_unlink',
        182: 'mq_timedsend',
        183: 'mq_timedreceive',
        184: 'mq_notify',
        185: 'mq_getsetattr',
        186: 'msgget',
        187: 'msgctl',
        188: 'msgrcv',
        189: 'msgsnd',
        190: 'semget',
        191: 'semctl',
        192: 'semtimedop',
        193: 'semop',
        194: 'shmget',
        195: 'shmctl',
        196: 'shmat',
        197: 'shmdt',
        198: 'socket',
        199: 'socketpair',
        200: 'bind',
        201: 'listen',
        202: 'accept',
        203: 'connect',
        204: 'getsockname',
        205: 'getpeername',
        206: 'sendto',
        207: 'recvfrom',
        208: 'setsockopt',
        209: 'getsockopt',
        210: 'shutdown',
        211: 'sendmsg',
        212: 'recvmsg',
        213: 'readahead',
        214: 'brk',
        215: 'munmap',
        216: 'mremap',
        217: 'add_key',
        218: 'request_key',
        219: 'keyctl',
        220: 'clone',
        221: 'execve',
        222: 'mmap',
        223: 'fadvise64',
        224: 'swapon',
        225: 'swapoff',
        226: 'mprotect',
        227: 'msync',
        228: 'mlock',
        229: 'munlock',
        230: 'mlockall',
        231: 'munlockall',
        232: 'mincore',
        233: 'madvise',
        234: 'remap_file_pages',
        235: 'mbind',
        236: 'get_mempolicy',
        237: 'set_mempolicy',
        238: 'migrate_pages',
        239: 'move_pages',
        240: 'rt_tgsigqueueinfo',
        241: 'perf_event_open',
        242: 'accept4',
        243: 'recvmmsg',
        244: 'arch_specific_syscall',
        260: 'wait4',
        261: 'prlimit64',
        262: 'fanotify_init',
        263: 'fanotify_mark',
        264: 'name_to_handle_at',
        265: 'open_by_handle_at',
        266: 'clock_adjtime',
        267: 'syncfs',
        268: 'setns',
        269: 'sendmmsg',
        270: 'process_vm_readv',
        271: 'process_vm_writev',
        272: 'kcmp',
        273: 'finit_module',
        274: 'sched_setattr',
        275: 'sched_getattr',
        276: 'renameat2',
        277: 'seccomp',
        278: 'getrandom',
        279: 'memfd_create',
        280: 'bpf',
        281: 'execveat',
        282: 'userfaultfd',
        283: 'membarrier',
        284: 'mlock2',
        285: 'copy_file_range',
        286: 'preadv2',
        287: 'pwritev2',
        288: 'pkey_mprotect',
        289: 'pkey_alloc',
        290: 'pkey_free',
        291: 'statx',
        292: 'syscalls'
    }
    Process.findModuleByName('linker64').enumerateSymbols().forEach(function(sym) {
        if (sym.name.indexOf('do_dlopen') >= 0) {
            do_dlopen = sym.address;
        } else if (sym.name.indexOf('call_constructor') >= 0) {
            call_ctor = sym.address;
        }
    })
    Interceptor.attach(do_dlopen, function() {
        var lib = this.context['x0'].readUtf8String();
        if (lib && lib.indexOf(ourlib) > -1) {
            Interceptor.attach(call_ctor, function() {
              /*
               Enabled it to Stop Tracing When Same Lib Loaded Again. 
              */
               // Interceptor.detachAll();               
                const mod = Process.findModuleByName(ourlib);
                mod.enumerateRanges('--x').forEach(function(range) {
                    Memory.scanSync(range.base, range.size, '01 00 00 d4').forEach(function(match) {
                        Interceptor.attach(match.address, function() {
                            var sc = parseInt(this.context['x8']);
                              console.log('syscall : ', SyscallNumber[sc] + '(' + sc + ')');
                            if (sc == 48 || sc == 27 || sc == 33 || sc == 34 || sc == 35 || sc == 78 || sc == 79) {
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), match.address);
                            }
                            if (sc == 56) {
                                //openat
                                var Maps = Memory.readCString(this.context['x1']);
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), match.address);
                                if (Maps.indexOf("/proc/" >= 0) && Maps.indexOf("maps") >= 0) {
                                  // this.context['x1'].writeUtf8String("/proc/self/mounts");
                                }
                            }
                            if (sc == 36) {
                                //symlinkat
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']), ' :---->> ', Memory.readCString(this.context['x2']));
                            }
                            if (sc == 37 || sc == 38 || sc == 276) {
                                //linkat renameat renameat2
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), ' :---->> ', Memory.readCString(this.context['x3']));
                            }
                            if (sc == 40) {
                                //mount
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']), ' :---->> ', Memory.readCString(this.context['x1']));
                            }
                            if (sc == 49 || sc == 51) {
                                //chdir chroot
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']));
                            }
                            if (sc == 63) {
                                //read (comment if large output)
                                // console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']));
                            }
                            if (sc == 64) {
                                //write
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']));
                            }
                            if (sc == 93) {
                                //exit
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', this.context['x0'].toInt32());
                            }
                            if (sc == 131) {
                                //tgkill
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', this.context['x1'].toInt32(), "Kill Detected");
                                //this.context['x1'].writeLong(11111)
                            }
                            if (sc == 221) {
                                //execve
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']), Memory.readCString(this.context['x1']), Memory.readCString(this.context['x2']));
                            }
                            if (sc == 281) {
                                //execveat
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), Memory.readCString(this.context['x2']), Memory.readCString(this.context['x3']));
                            }
                        });
                    });
                });
            })
        }
    });
    Interceptor.attach(Module.getExportByName('libc.so', 'syscall'), {
        onEnter: function(args) {
            var sc = parseInt(args[0].toInt32());
            console.log('libc syscall : ', SyscallNumber[sc] + '(' + sc + ')');
            if (sc == 48 || sc == 27 || sc == 33 || sc == 34 || sc == 35 || sc == 78 || sc == 79) {
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), match.address);
            }
            if (sc == 56) {
                //openat
                var Maps = Memory.readCString(this.context['x1']);
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), match.address);
                if (Maps.indexOf("/proc/" >= 0) && Maps.indexOf("maps") >= 0) {
                    //  this.context['x1'].writeUtf8String("/proc/self/mounts");
                }
            }
            if (sc == 36) {
                //symlinkat
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']), ' :---->> ', Memory.readCString(this.context['x2']));
            }
            if (sc == 37 || sc == 38 || sc == 276) {
                //linkat renameat renameat2
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), ' :---->> ', Memory.readCString(this.context['x3']));
            }
            if (sc == 40) {
                //mount
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']), ' :---->> ', Memory.readCString(this.context['x1']));
            }
            if (sc == 49 || sc == 51) {
                //chdir chroot
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']));
            }
            if (sc == 63) {
                //read (comment if large output)
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']));
            }
            if (sc == 64) {
                //write
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']));
            }
            if (sc == 93) {
                //exit
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', this.context['x0'].toInt32());
            }
            if (sc == 131) {
                //tgkill
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', this.context['x1'].toInt32(), "Kill Detected");
                //this.context['x1'].writeLong(11111)
            }
            if (sc == 221) {
                //execve
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x0']), Memory.readCString(this.context['x1']), Memory.readCString(this.context['x2']));
            }
            if (sc == 281) {
                //execveat
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['x1']), Memory.readCString(this.context['x2']), Memory.readCString(this.context['x3']));
            }
        }
    });
} else
if (Process.arch == "arm") {
    var do_dlopen = null;
    var call_ctor = null;
    var SyscallNumber = {
        0: 'restart_syscall',
        1: 'exit',
        2: 'fork',
        3: 'read',
        4: 'write',
        5: 'open',
        6: 'close',
        8: 'creat',
        9: 'link',
        10: 'unlink',
        11: 'execve',
        12: 'chdir',
        14: 'mknod',
        15: 'chmod',
        16: 'lchown',
        19: 'lseek',
        20: 'getpid',
        21: 'mount',
        23: 'setuid',
        24: 'getuid',
        26: 'ptrace',
        29: 'pause',
        33: 'access',
        34: 'nice',
        36: 'sync',
        37: 'kill',
        38: 'rename',
        39: 'mkdir',
        40: 'rmdir',
        41: 'dup',
        42: 'pipe',
        43: 'times',
        45: 'brk',
        46: 'setgid',
        47: 'getgid',
        49: 'geteuid',
        50: 'getegid',
        51: 'acct',
        52: 'umount2',
        54: 'ioctl',
        55: 'fcntl',
        57: 'setpgid',
        60: 'umask',
        61: 'chroot',
        62: 'ustat',
        63: 'dup2',
        64: 'getppid',
        65: 'getpgrp',
        66: 'setsid',
        67: 'sigaction',
        70: 'setreuid',
        71: 'setregid',
        72: 'sigsuspend',
        73: 'sigpending',
        74: 'sethostname',
        75: 'setrlimit',
        77: 'getrusage',
        78: 'gettimeofday',
        79: 'settimeofday',
        80: 'getgroups',
        81: 'setgroups',
        83: 'symlink',
        85: 'readlink',
        86: 'uselib',
        87: 'swapon',
        88: 'reboot',
        91: 'munmap',
        92: 'truncate',
        93: 'ftruncate',
        94: 'fchmod',
        95: 'fchown',
        96: 'getpriority',
        97: 'setpriority',
        99: 'statfs',
        100: 'fstatfs',
        103: 'syslog',
        104: 'setitimer',
        105: 'getitimer',
        106: 'stat',
        107: 'lstat',
        108: 'fstat',
        111: 'vhangup',
        114: 'wait4',
        115: 'swapoff',
        116: 'sysinfo',
        118: 'fsync',
        119: 'sigreturn',
        120: 'clone',
        121: 'setdomainname',
        122: 'uname',
        124: 'adjtimex',
        125: 'mprotect',
        126: 'sigprocmask',
        128: 'init_module',
        129: 'delete_module',
        131: 'quotactl',
        132: 'getpgid',
        133: 'fchdir',
        134: 'bdflush',
        135: 'sysfs',
        136: 'personality',
        138: 'setfsuid',
        139: 'setfsgid',
        140: '_llseek',
        141: 'getdents',
        142: '_newselect',
        143: 'flock',
        144: 'msync',
        145: 'readv',
        146: 'writev',
        147: 'getsid',
        148: 'fdatasync',
        149: '_sysctl',
        150: 'mlock',
        151: 'munlock',
        152: 'mlockall',
        153: 'munlockall',
        154: 'sched_setparam',
        155: 'sched_getparam',
        156: 'sched_setscheduler',
        157: 'sched_getscheduler',
        158: 'sched_yield',
        159: 'sched_get_priority_max',
        160: 'sched_get_priority_min',
        161: 'sched_rr_get_erval',
        162: 'nanosleep',
        163: 'mremap',
        164: 'setresuid',
        165: 'getresuid',
        168: 'poll',
        169: 'nfsservctl',
        170: 'setresgid',
        171: 'getresgid',
        172: 'prctl',
        173: 'rt_sigreturn',
        174: 'rt_sigaction',
        175: 'rt_sigprocmask',
        176: 'rt_sigpending',
        177: 'rt_sigtimedwait',
        178: 'rt_sigqueueinfo',
        179: 'rt_sigsuspend',
        180: 'pread64',
        181: 'pwrite64',
        182: 'chown',
        183: 'getcwd',
        184: 'capget',
        185: 'capset',
        186: 'sigaltstack',
        187: 'sendfile',
        190: 'vfork',
        191: 'ugetrlimit',
        192: 'mmap2',
        193: 'truncate64',
        194: 'ftruncate64',
        195: 'stat64',
        196: 'lstat64',
        197: 'fstat64',
        198: 'lchown32',
        199: 'getuid32',
        200: 'getgid32',
        201: 'geteuid32',
        202: 'getegid32',
        203: 'setreuid32',
        204: 'setregid32',
        205: 'getgroups32',
        206: 'setgroups32',
        207: 'fchown32',
        208: 'setresuid32',
        209: 'getresuid32',
        210: 'setresgid32',
        211: 'getresgid32',
        212: 'chown32',
        213: 'setuid32',
        214: 'setgid32',
        215: 'setfsuid32',
        216: 'setfsgid32',
        217: 'getdents64',
        218: 'pivot_root',
        219: 'mincore',
        220: 'madvise',
        221: 'fcntl64',
        224: 'gettid',
        225: 'readahead',
        226: 'setxattr',
        227: 'lsetxattr',
        228: 'fsetxattr',
        229: 'getxattr',
        230: 'lgetxattr',
        231: 'fgetxattr',
        232: 'listxattr',
        233: 'llistxattr',
        234: 'flistxattr',
        235: 'removexattr',
        236: 'lremovexattr',
        237: 'fremovexattr',
        238: 'tkill',
        239: 'sendfile64',
        240: 'futex',
        241: 'sched_setaffinity',
        242: 'sched_getaffinity',
        243: 'io_setup',
        244: 'io_destroy',
        245: 'io_getevents',
        246: 'io_submit',
        247: 'io_cancel',
        248: 'exit_group',
        249: 'lookup_dcookie',
        250: 'epoll_create',
        251: 'epoll_ctl',
        252: 'epoll_wait',
        253: 'remap_file_pages',
        256: 'set_tid_address',
        257: 'timer_create',
        258: 'timer_settime',
        259: 'timer_gettime',
        260: 'timer_getoverrun',
        261: 'timer_delete',
        262: 'clock_settime',
        263: 'clock_gettime',
        264: 'clock_getres',
        265: 'clock_nanosleep',
        266: 'statfs64',
        267: 'fstatfs64',
        268: 'tgkill',
        269: 'utimes',
        270: 'arm_fadvise64_64',
        271: 'pciconfig_iobase',
        272: 'pciconfig_read',
        273: 'pciconfig_write',
        274: 'mq_open',
        275: 'mq_unlink',
        276: 'mq_timedsend',
        277: 'mq_timedreceive',
        278: 'mq_notify',
        279: 'mq_getsetattr',
        280: 'waitid',
        281: 'socket',
        282: 'bind',
        283: 'connect',
        284: 'listen',
        285: 'accept',
        286: 'getsockname',
        287: 'getpeername',
        288: 'socketpair',
        289: 'send',
        290: 'sendto',
        291: 'recv',
        292: 'recvfrom',
        293: 'shutdown',
        294: 'setsockopt',
        295: 'getsockopt',
        296: 'sendmsg',
        297: 'recvmsg',
        298: 'semop',
        299: 'semget',
        300: 'semctl',
        301: 'msgsnd',
        302: 'msgrcv',
        303: 'msgget',
        304: 'msgctl',
        305: 'shmat',
        306: 'shmdt',
        307: 'shmget',
        308: 'shmctl',
        309: 'add_key',
        310: 'request_key',
        311: 'keyctl',
        312: 'semtimedop',
        313: 'vserver',
        314: 'ioprio_set',
        315: 'ioprio_get',
        316: 'inotify_init',
        317: 'inotify_add_watch',
        318: 'inotify_rm_watch',
        319: 'mbind',
        320: 'get_mempolicy',
        321: 'set_mempolicy',
        322: 'openat',
        323: 'mkdirat',
        324: 'mknodat',
        325: 'fchownat',
        326: 'futimesat',
        327: 'fstatat64',
        328: 'unlinkat',
        329: 'renameat',
        330: 'linkat',
        331: 'symlinkat',
        332: 'readlinkat',
        333: 'fchmodat',
        334: 'faccessat',
        335: 'pselect6',
        336: 'ppoll',
        337: 'unshare',
        338: 'set_robust_list',
        339: 'get_robust_list',
        340: 'splice',
        341: 'arm_sync_file_range',
        341: 'sync_file_range2',
        342: 'tee',
        343: 'vmsplice',
        344: 'move_pages',
        345: 'getcpu',
        346: 'epoll_pwait',
        347: 'kexec_load',
        348: 'utimensat',
        349: 'signalfd',
        350: 'timerfd_create',
        351: 'eventfd',
        352: 'fallocate',
        353: 'timerfd_settime',
        354: 'timerfd_gettime',
        355: 'signalfd4',
        356: 'eventfd2',
        357: 'epoll_create1',
        358: 'dup3',
        359: 'pipe2',
        360: 'inotify_init1',
        361: 'preadv',
        362: 'pwritev',
        363: 'rt_tgsigqueueinfo',
        364: 'perf_event_open',
        365: 'recvmmsg',
        366: 'accept4',
        367: 'fanotify_init',
        368: 'fanotify_mark',
        369: 'prlimit64',
        370: 'name_to_handle_at',
        371: 'open_by_handle_at',
        372: 'clock_adjtime',
        373: 'syncfs',
        374: 'sendmmsg',
        375: 'setns',
        376: 'process_vm_readv',
        377: 'process_vm_writev',
        378: 'kcmp',
        379: 'finit_module',
        380: 'sched_setattr',
        381: 'sched_getattr',
        382: 'renameat2',
        383: 'seccomp',
        384: 'getrandom',
        385: 'memfd_create',
        386: 'bpf',
        387: 'execveat',
        388: 'userfaultfd',
        389: 'membarrier',
        390: 'mlock2',
        391: 'copy_file_range',
        392: 'preadv2',
        393: 'pwritev2',
        394: 'pkey_mprotect',
        395: 'pkey_alloc',
        396: 'pkey_free',
        397: 'statx'
    }
    Process.findModuleByName('linker').enumerateSymbols().forEach(function(sym) {
        if (sym.name.indexOf('do_dlopen') >= 0) {
            do_dlopen = sym.address;
        } else if (sym.name.indexOf('call_constructor') >= 0) {
            call_ctor = sym.address;
        }
    })
    Interceptor.attach(do_dlopen, function() {
        var lib = this.context['r0'].readUtf8String();
        if (lib && lib.indexOf(ourlib) > -1) {
            Interceptor.attach(call_ctor, function() {
                Interceptor.detachAll();
                const mod = Process.findModuleByName(ourlib);
                mod.enumerateRanges('--x').forEach(function(range) {
                  /*
				   Here is a case for arm as thumb mod mixing make it hard so 
				   if "01 27 00 df" not work then try "00 00 00 ef" and if this also not work then do "00 00 00 df"	
				   still no guarantee that it will work . fuck arm complexity
				   
				   and in place of 
				   Interceptor.attach(match.address, function() {
                   you can do if any issue is there
                   Interceptor.attach(match.address.add(1), function() {
				  	
				 */ 
                    Memory.scanSync(range.base, range.size, '01 27 00 df').forEach(function(match) {
                        Interceptor.attach(match.address, function() {
                            var sc = parseInt(this.context['r7']);
                              console.log('syscall : ', SyscallNumber[sc] + '(' + sc + ')');
                            if (sc == 38 || sc == 83 || sc == 226 || sc == 227 || sc == 229 || sc == 230 || sc == 232 || sc == 233 || sc == 235 || sc == 236) {
                                //rename symlink setxattr lsetxattr getxattr lgetxattr listxattr llistxattr removexattr lremovexattr 
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']), ' :---->> ', Memory.readCString(this.context['r1']));
                            }
                            if (sc == 8 || sc == 10 || sc == 12 || sc == 14 || sc == 15 || sc == 16 || sc == 33 || sc == 39 || sc == 40 || sc == 61 || sc == 85 || sc == 86 || sc == 99 || sc == 106 || sc == 107 || sc == 182 || sc == 195 || sc == 196 || sc == 266 || sc == 274 || sc == 275) {
                                //create unlink chdir mknod chmod lchown access mkdir rmdir chroot readlink uselib statfs stat lstat chown stat64 lstat64 statfs64 mq_open mq_unlink
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']));
                            }
                            if (sc == 228 || sc == 231 || sc == 234 || sc == 237 || sc == 322 || sc == 323 || sc == 324 || sc == 325 || sc == 326 || sc == 327 || sc == 328 || sc == 332 || sc == 333 || sc == 334 || sc == 397) {
                                //fsetxattr fgetxattr flistxattr fremovexattr openat mkdirat mknodat fchownat futimesat fstatat64 unlinkat readlinkat fchmodat faccessat statx
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']));
                            }
                            if (sc == 5) {
                                //open
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']));
                            }
                            if (sc == 3) {
                                //read (comment if large output)
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']));
                            }
                            if (sc == 4) {
                                //write
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']));
                            }
                            if (sc == 11 || sc == 21) {
                                //execve mount
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']), Memory.readCString(this.context['r1']), Memory.readCString(this.context['r2']));
                            }
                            if (sc == 329 || sc == 330 || sc == 382) {
                                //renameat linkat renameat2
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']), Memory.readCString(this.context['r3']));
                            }
                            if (sc == 331) {
                                //symlinkat
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']), Memory.readCString(this.context['r2']));
                            }
                            if (sc == 387) {
                                //execve mount
                                console.log('Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']), Memory.readCString(this.context['r2']), Memory.readCString(this.context['r3']));
                            }
                        })
                    });
                });
            })
        }
    });
    Interceptor.attach(Module.getExportByName('libc.so', 'syscall'), {
        onEnter: function(args) {
            var sc = parseInt(args[0].toInt32());
            console.log('libc syscall : ', SyscallNumber[sc] + '(' + sc + ')');
            if (sc == 38 || sc == 83 || sc == 226 || sc == 227 || sc == 229 || sc == 230 || sc == 232 || sc == 233 || sc == 235 || sc == 236) {
                //rename symlink setxattr lsetxattr getxattr lgetxattr listxattr llistxattr removexattr lremovexattr 
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']), ' :---->> ', Memory.readCString(this.context['r1']));
            }
            if (sc == 8 || sc == 10 || sc == 12 || sc == 14 || sc == 15 || sc == 16 || sc == 33 || sc == 39 || sc == 40 || sc == 61 || sc == 85 || sc == 86 || sc == 99 || sc == 106 || sc == 107 || sc == 182 || sc == 195 || sc == 196 || sc == 266 || sc == 274 || sc == 275) {
                //create unlink chdir mknod chmod lchown access mkdir rmdir chroot readlink uselib statfs stat lstat chown stat64 lstat64 statfs64 mq_open mq_unlink
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']));
            }
            if (sc == 228 || sc == 231 || sc == 234 || sc == 237 || sc == 322 || sc == 323 || sc == 324 || sc == 325 || sc == 326 || sc == 327 || sc == 328 || sc == 332 || sc == 333 || sc == 334 || sc == 397) {
                //fsetxattr fgetxattr flistxattr fremovexattr openat mkdirat mknodat fchownat futimesat fstatat64 unlinkat readlinkat fchmodat faccessat statx
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']));
            }
            if (sc == 5) {
                //open
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']));
            }
            if (sc == 3) {
                //read (comment if large output)
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']));
            }
            if (sc == 4) {
                //write
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']));
            }
            if (sc == 11 || sc == 21) {
                //execve mount
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']), Memory.readCString(this.context['r1']), Memory.readCString(this.context['r2']));
            }
            if (sc == 329 || sc == 330 || sc == 382) {
                //renameat linkat renameat2
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']), Memory.readCString(this.context['r3']));
            }
            if (sc == 331) {
                //symlinkat
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r0']), Memory.readCString(this.context['r2']));
            }
            if (sc == 387) {
                //execve mount
                console.log('Libc Syscall :', SyscallNumber[sc] + '(' + sc + ')', Memory.readCString(this.context['r1']), Memory.readCString(this.context['r2']), Memory.readCString(this.context['r3']));
            }
        }
    });
}