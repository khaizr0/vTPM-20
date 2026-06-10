# vTPM2

# 🚧 WORK IN PROGRESS (WIP) - UNDER ACTIVE DEVELOPMENT 🚧

> 💡 **Note**: This is a personal hobby project created purely for fun and educational purposes.
> 📅 **ETA**: TBD (Developed in my spare time, progress depends on interest/availability).

Experimental Windows software TPM 2.0 (TpmPresent/TpmReady/Storage/Attestation: True).

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
- **`VtpmPreboot.efi`**: EFI loader that injects custom ACPI tables (`MSFT0101`) at boot.
- **`vtpm.sys` (Kernel Driver)**: Root-enumerated TPM driver that intercepts commands/IOCTLs and loads event logs.
- **`vtpm_service.exe` (Service)**: Bridge handling EK certs, SRK queries, and measured boot sync.
- **`Simulator.exe`**: Core TPM 2.0 cryptoprocessor (Microsoft Reference Implementation).

Repository contains source code and scripts only; build artifacts are excluded.

---

## 🔒 Proof

<img width="880" src="https://github.com/user-attachments/assets/237bdba0-8bc6-49c0-a63b-3b78a9463fcb" />

<details>
<summary>Old</summary>

<br/>

<img width="800" alt="vTpm-20 Verification Proof" src="https://github.com/user-attachments/assets/3c0a7ca6-be74-4e15-b8b4-d77f69a735ee" />

</details>

---

## Requirements
- Windows 11 x64 (Host/Guest, Admin)
- VS 2022 + WDK
- VirtualBox (VM only - experimental phase; architecture & code will be fully revised later)

## Build & Test
1. **Build (Host):** Run `.\build_driver_variants.ps1` and `.\package_kernel_poc.ps1`.
2. **Configure VM (Host):** `.\configure_vbox_acpi_vtpm.ps1 -VmName win11`
3. **Install (Guest):** Copy `release-kernel-poc` to guest, run `install_acpi_platform_vtpm.ps1` (Admin), and reboot.
4. **Verify (Guest):** Run `tpmtool getdeviceinformation`
5. **Rollback (Host):** `.\remove_vbox_acpi_vtpm.ps1 -VmName win11`

---

## 📅 Todo List (Roadmap)

### Core Integration
- [x] Forward TPM commands/IOCTLs (`vtpm.sys` $\leftrightarrow$ `vtpm_service.exe`)
- [x] Proxy executions to MS TPM reference simulator
- [x] Read measured boot logs from `C:\Windows\Logs\MeasuredBoot\`
- [x] Sync boot logs to simulator PCRs (resolves `TBS_E_NO_EVENT_LOG`)
- [x] Generate & register EK Certs in registry (`EKCertStore`)
- [x] Handle SRK public key queries (`IOCTL_TPM_GET_PERSISTENT_PUBLIC`)
- [x] Replay registry-based event logs in driver init
- [x] Inject dynamic ACPI tables via EFI loader (`VtpmPreboot.efi`)

### Security & Hardening
- [ ] Encrypt and lock simulator NV state
- [ ] Add anti-rollback metadata (clock sync, reset/restart counters)
- [ ] Generate synthetic WBCL event log streams
- [ ] Test with Windows Hello & BitLocker
- [ ] Driver production signing setup
- [ ] ... and more

---

## ⚠️ Disclaimer
- **Signing:** Requires Windows Test Mode (`TESTSIGNING`) or WHQL signature.
- **Security:** Research software. Do not use for production secrets, BitLocker, or actual attestation.
