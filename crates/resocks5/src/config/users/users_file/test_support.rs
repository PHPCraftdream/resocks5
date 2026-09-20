use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

const SE_FILE_OBJECT: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_PROTECTED: u16 = 0x1000;
const ACL_SIZE_INFORMATION_CLASS: u32 = 2;

#[repr(C)]
#[derive(Default)]
struct AclSizeInformation {
    ace_count: u32,
    bytes_in_use: u32,
    bytes_free: u32,
}

#[link(name = "advapi32")]
extern "system" {
    fn GetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        security_descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorControl(sd: *mut c_void, control: *mut u16, revision: *mut u32) -> i32;
    fn GetAclInformation(
        acl: *mut c_void,
        information: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hmem: *mut c_void) -> *mut c_void;
}

struct LocalDescriptor(*mut c_void);
impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: this descriptor is owned and allocated by GetNamedSecurityInfoW.
        unsafe { LocalFree(self.0) };
    }
}

pub(crate) fn assert_owner_only_dacl(path: &Path) {
    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    // SAFETY: path_w is terminated and all output pointers are valid.
    // On success, sd owns the allocation containing owner and dacl.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    assert_eq!(rc, 0, "GetNamedSecurityInfoW failed");
    let sd = LocalDescriptor(sd);
    assert!(!sd.0.is_null());
    assert!(!owner.is_null(), "SD must have an owner");
    assert!(!dacl.is_null(), "DACL must not grant unrestricted access");

    let mut control = 0;
    let mut revision = 0;
    // SAFETY: sd is live and valid; both output slots match the Win32 ABI.
    let ok = unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) };
    assert_ne!(ok, 0, "GetSecurityDescriptorControl failed");
    assert_ne!(control & SE_DACL_PRESENT, 0);
    assert_ne!(control & SE_DACL_PROTECTED, 0);

    let mut info = AclSizeInformation::default();
    // SAFETY: dacl is inside the live sd; class 2 writes this repr(C) layout.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<AclSizeInformation>() as u32,
            ACL_SIZE_INFORMATION_CLASS,
        )
    };
    assert_ne!(ok, 0, "GetAclInformation failed");
    assert_eq!(info.ace_count, 1, "only the owner-rights ACE is allowed");

    let mut ace = std::ptr::null_mut();
    // SAFETY: dacl is live and contains one ACE; ace is a valid output slot.
    let ok = unsafe { GetAce(dacl, 0, &mut ace) };
    assert_ne!(ok, 0, "GetAce failed");
    assert!(!ace.is_null());
    // SAFETY: every valid ACE begins with the four-byte ACE_HEADER.
    let header = unsafe { std::ptr::read_unaligned(ace.cast::<[u8; 4]>()) };
    assert_eq!(header[0], 0, "ACCESS_ALLOWED_ACE expected");
    assert_eq!(header[1], 0, "no inherited or inheritable flags");
    let ace_size = u16::from_le_bytes([header[2], header[3]]);
    assert_eq!(ace_size, 20, "owner-rights ACE has a twelve-byte SID");
    // SAFETY: GetAce returned a valid ACE; its checked size covers these bytes.
    let body = unsafe { std::ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<[u8; 16]>()) };
    let mask = u32::from_le_bytes(body[..4].try_into().unwrap());
    assert_eq!(mask, 0x001F_01FF, "FILE_ALL_ACCESS expected");
    assert_eq!(
        &body[4..],
        &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0],
        "S-1-3-4 expected"
    );
}
