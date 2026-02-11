use windows::Win32::Foundation::NTSTATUS;

pub fn nt_success(status: NTSTATUS) -> bool {
    status.0 >= 0
}
