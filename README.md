# vTpm-20

# 🚧 WORK IN PROGRESS (WIP) - UNDER ACTIVE DEVELOPMENT 🚧

> 💡 **Note**: This is a personal hobby project created purely for fun and educational purposes.
> 📅 **ETA**: TBD (Developed in my spare time, progress depends on interest/availability).

---

## ⚙️ How It Works (Architecture)

<details>
<summary>New</summary>

<br/>

<img width="600" height="600" alt="vTpm-20 New Architecture Flow Diagram" src="https://github.com/user-attachments/assets/9c2ee263-6201-4b57-95c3-6fc5f5d999fc" />

</details>

<details>
<summary>Old</summary>

<br/>

<img width="1020" alt="vTpm-20 Architecture Flow Diagram" src="https://github.com/user-attachments/assets/06d00983-c480-47e7-a7ed-80567b95a495" />

</details>

A software-based **Virtual Trusted Platform Module (vTPM) 2.0** implementation designed to satisfy Windows 11's security requirements by emulating a fully functional TPM 2.0 device.

- ~~**Kernel-Mode Driver (`vtpm.sys`)**: Intercepts standard TPM commands and IOCTLs from Windows.~~
- ~~**User-Mode Service Bridge (`vtpm_service.exe`)**: Proxies commands to the simulator, reads Measured Boot logs, replays PCR extensions, and registers the EK certificate in the Registry.~~
- ~~**TPM 2.0 Simulator (`Simulator.exe`)**: Handles core TPM 2.0 cryptographic operations (based on Microsoft's reference implementation [ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref)).~~
- **Pre-Boot ACPI Table Injector (`VtpmPreboot.efi`)**: A standalone EFI application that dynamically registers custom `MSFT0101` TPM2 ACPI tables at boot time. This tells the Windows kernel that a TPM device is present on the hardware (or VM) level without requiring physical TPM hardware.
- **Kernel-Mode Driver (`vtpm.sys` / `KernelTpm.c`)**: Registers a root-enumerated TPM device, intercepts standard Windows TPM commands and IOCTLs, and handles basic capability queries and PCR read/extend operations. It also features a built-in registry-based boot log loader (`LoadEventLog`) to replay boot events during driver initialization.
- **User-Mode Service Bridge (`vtpm_service.exe`)**: Links the kernel driver to the simulator. It handles Endorsement Key (EK) certificate generation, registers it under `EKCertStore`, resolves the Storage Root Key (SRK) query via `IOCTL_TPM_GET_PERSISTENT_PUBLIC`, parses Measured Boot logs from `C:\Windows\Logs\MeasuredBoot\`, and replays/syncs PCR states.
- **TPM 2.0 Simulator (`Simulator.exe`)**: Implements core TPM 2.0 cryptographic operations based on Microsoft's reference implementation ([ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref)).

---

## 🔒 Proof

<img width="880" src="https://github.com/user-attachments/assets/237bdba0-8bc6-49c0-a63b-3b78a9463fcb" />

<details>
<summary>Old</summary>

<br/>

<img width="800" alt="vTpm-20 Verification Proof" src="https://github.com/user-attachments/assets/3c0a7ca6-be74-4e15-b8b4-d77f69a735ee" />

</details>

---

## 📅 Todo List (Roadmap)

### Core Integration
- [x] Integrate standard Windows TPM commands and IOCTL forwarding (`vtpm.sys` $\leftrightarrow$ `vtpm_service.exe`)
- [x] Proxy TPM execution loops to the MS TPM reference simulator
- [x] Read Measured Boot logs dynamically from Windows disk (`C:\Windows\Logs\MeasuredBoot\`)
- [x] Replay and sync boot logs into the simulator's PCR banks on startup (resolving `TBS_E_NO_EVENT_LOG`)
- [x] Autonomously provision and register EK Certificates in the Windows Registry (`EKCertStore`)
- [x] Handle Storage Root Key (SRK) Public Key queries (`IOCTL_TPM_GET_PERSISTENT_PUBLIC`)
- [x] Registry-based Measured Boot log replay (`SrtmEventLog`) within kernel driver initialization
- [x] Standalone pre-boot loader (`VtpmPreboot.efi`) for dynamic ACPI table injection

### Security & Production Hardening
- [ ] Implement machine-locked state persistence and encryption for the simulator's NV state
- [ ] Support anti-rollback metadata (clock synchronization, reset and restart counts)
- [ ] Implement custom synthetic WBCL event log stream generator
- [ ] Conduct full compatibility testing with Windows Hello & BitLocker data volume protectors
- [ ] Driver production signing setup for non-Test Mode Windows environments
- [ ] ... and more
