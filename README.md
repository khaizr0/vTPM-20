# vTpm-20

# 🚧 WORK IN PROGRESS (WIP) - UNDER ACTIVE DEVELOPMENT 🚧

> 💡 **Note**: This is a personal hobby project created purely for fun and educational purposes.
> 📅 **ETA**: TBD (Developed in my spare time, progress depends on interest/availability).

---

## ⚙️ How It Works (Architecture)

<img width="1020" height="200" alt="vTpm-20 Architecture Flow Diagram" src="https://github.com/user-attachments/assets/06d00983-c480-47e7-a7ed-80567b95a495" />

A software-based **Virtual Trusted Platform Module (vTPM) 2.0** implementation designed to satisfy Windows 11's security requirements by emulating a fully functional TPM 2.0 device.

- **Kernel-Mode Driver (`vtpm.sys`)**: Intercepts standard TPM commands and IOCTLs from Windows.
- **User-Mode Service Bridge (`vtpm_service.exe`)**: Proxies commands to the simulator, reads Measured Boot logs, replays PCR extensions, and registers the EK certificate in the Registry.
- **TPM 2.0 Simulator (`Simulator.exe`)**: Handles core TPM 2.0 cryptographic operations (based on Microsoft's reference implementation [ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref)).

---

## 🔒 Proof

<img width="800" alt="vTpm-20 Verification Proof" src="https://github.com/user-attachments/assets/3c0a7ca6-be74-4e15-b8b4-d77f69a735ee" />

---

## 📅 Todo List (Roadmap)

### Core Integration
- [x] Integrate standard Windows TPM commands and IOCTL forwarding (`vtpm.sys` $\leftrightarrow$ `vtpm_service.exe`)
- [x] Proxy TPM execution loops to the MS TPM reference simulator
- [x] Read Measured Boot logs dynamically from Windows disk (`C:\Windows\Logs\MeasuredBoot\`)
- [x] Replay and sync boot logs into the simulator's PCR banks on startup (resolving `TBS_E_NO_EVENT_LOG`)
- [x] Autonomously provision and register EK Certificates in the Windows Registry (`EKCertStore`)

### Security & Production Hardening
- [ ] Implement machine-locked state persistence and encryption for the simulator's NV state
- [ ] Support anti-rollback metadata (clock synchronization, reset and restart counts)
- [ ] Implement custom synthetic WBCL event log stream generator
- [ ] Conduct full compatibility testing with Windows Hello & BitLocker data volume protectors
- [ ] Driver production signing setup for non-Test Mode Windows environments
- [ ] ... and more
