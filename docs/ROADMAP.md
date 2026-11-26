# Roadmap

This is the plan, not a promise. Things move between versions as we learn. There are no dates: a version ships when it passes its checks on all six reference machines.

"Done" means the applicable checks passed on one build across the six reference machines, with explicit exceptions and emulator-equivalent checks stated below. Everything else is planned or in progress.

## 0.1 Preview: a solid base you can try

**Done** (14 of 47 required items when this snapshot was made), as tested on our current hardware:
- One PaOS image that starts on all six reference machines
- The core Secure Boot chain: tampered boot files are refused (the full try-and-install journey isn't checked yet)
- Recovery from a bad start
- All processor cores in use; hardware discovery; interrupts and clocks; memory protection
- Hardware error handling
- Common driver framework, where each device reports its real state, including when it is limited or not working
- The old separate Console retired from view in favour of Terminal: it is hidden, never opens by itself and has no Start entry; a protected recovery path stays
- Cryptography and identity base
- Disk sector geometry: 512-byte transfers on four machines (not applicable on the Dell and HP); unsupported 4Kn geometry refused before I/O and never reported healthy, checked with emulator equivalents. One transfer result was regraded from its saved original after a grader correction. Broader disk compatibility is planned for 0.2
- System information, including the measured device name, checked on all six machines

**In progress for 0.1:**
- Try from USB, approve the PaOS key, install to free space or a second disk
- Owner password, lock screen and sign-in
- Desktop, windows, Start menu and taskbar; Settings; Terminal; Explorer; wallpaper; clock
- Wired networking, Network Monitor, SSH in (off until you add a key) and SSH out
- Reading Windows and Linux drives; writing to PaOS's own partition and USB sticks
- Linux in a virtual machine, with Claude Code and Codex in the Terminal
- Network chips without a native driver, through the Linux guest
- Apps as single `.paosapp` files, with a permission card
- Typed commands (each with a fixed name and checked inputs) that scripts and AI tools can use, with your permission
- Failure records, a report you can send yourself, and USB repair in Rescue
- Published boot-time and reliability measurements
- Security: processor protections, signed updates, a public way to report security problems, and fuzz testing (feeding programs large amounts of malformed input to find bugs)

**Maybe in 0.1** (only if ready in time; never holds the release):
- Web browser in a window
- Local AI running on the processor
- Win+Space chat app

## 0.2: more of your hardware, more everyday use

- Sound, sleep and wake, and USB network adapters
- Windows and Linux desktop apps in a window
- Install by shrinking Windows, and writing to Windows and Linux drives
- More built-in apps and tools, and smaller updates

## 0.3

More languages, smarter safety and more AI features. Details later.

## Later

Wi-Fi, GPU acceleration for AI, and an outside security review before 1.0. Details later.
