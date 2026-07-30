#![allow(unsafe_code)]

use core::ffi::{c_char, c_void};
use core::ptr;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::mem::{offset_of, size_of};
use std::os::fd::{FromRawFd as _, OwnedFd};

use crate::NativeIdentityErrorV2;

const ERR_SEC_SUCCESS: i32 = 0;
const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
const K_SEC_CS_REQUIREMENT_INFORMATION: u32 = 1 << 2;
const TASK_AUDIT_TOKEN: i32 = 15;
const AUDIT_TOKEN_WORDS: u32 = 8;
const MAX_CODE_DIRECTORY_BYTES: usize = 4 * 1024;
const MAX_REQUIREMENT_BYTES: usize = 64 * 1024;
const MAX_ENTITLEMENT_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_UTF8_BYTES: usize = 255;
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROC_PIDFDSOCKETINFO_SIZE: usize = 792;

type CFIndex = isize;
type CFTypeId = usize;
type CFTypeRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFStringRef = *const c_void;
type CFDataRef = *const c_void;
type CFDictionaryRef = *const c_void;
type SecCodeRef = *const c_void;
type SecRequirementRef = *const c_void;

#[repr(C)]
struct ProcFileInfoV2 {
    open_flags: u32,
    status: u32,
    offset: i64,
    file_type: i32,
    guard_flags: u32,
}

#[repr(C)]
struct VinfoStatV2 {
    device: u32,
    mode: u16,
    link_count: u16,
    inode: u64,
    uid: u32,
    gid: u32,
    access_time: i64,
    access_time_nsec: i64,
    modification_time: i64,
    modification_time_nsec: i64,
    change_time: i64,
    change_time_nsec: i64,
    birth_time: i64,
    birth_time_nsec: i64,
    size: i64,
    blocks: i64,
    block_size: i32,
    flags: u32,
    generation: u32,
    raw_device: u32,
    spare: [i64; 2],
}

#[repr(C)]
struct SocketInfoPrefixV2 {
    stat: VinfoStatV2,
    socket: u64,
    protocol_control_block: u64,
    socket_type: i32,
    protocol: i32,
    family: i32,
    options: i16,
}

#[repr(C)]
struct SocketFdInfoPrefixV2 {
    file: ProcFileInfoV2,
    socket: SocketInfoPrefixV2,
}

#[repr(C, align(8))]
struct SocketFdInfoBufferV2([u8; PROC_PIDFDSOCKETINFO_SIZE]);

const _: [(); 24] = [(); size_of::<ProcFileInfoV2>()];
const _: [(); 136] = [(); size_of::<VinfoStatV2>()];
const _: [(); 164] = [(); offset_of!(SocketInfoPrefixV2, options)];
const _: [(); 24] = [(); offset_of!(SocketFdInfoPrefixV2, socket)];

pub(super) struct OwnedMacOsCodeIdentityV2 {
    pub(super) bundle_id: String,
    pub(super) team_id: String,
    pub(super) code_directory: Vec<u8>,
    pub(super) designated_requirement: Vec<u8>,
    pub(super) entitlements: Vec<u8>,
}

struct OwnedCf(CFTypeRef);

impl OwnedCf {
    fn new(value: CFTypeRef) -> Result<Self, NativeIdentityErrorV2> {
        if value.is_null() {
            Err(NativeIdentityErrorV2::CodeIdentityUnavailable)
        } else {
            Ok(Self(value))
        }
    }

    fn as_type(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: `OwnedCf` is created only for non-null objects returned at +1
        // ownership by Create/Copy APIs. It owns exactly one retain and drops once.
        unsafe { CFRelease(self.0) };
    }
}

pub(super) fn current_process_audit_token_v2() -> Result<[u8; 32], NativeIdentityErrorV2> {
    let mut token = [0_u32; AUDIT_TOKEN_WORDS as usize];
    let mut count = AUDIT_TOKEN_WORDS;
    // SAFETY: `mach_task_self_` is a process-global send right supplied by
    // libSystem. `token` has exactly TASK_AUDIT_TOKEN_COUNT natural_t slots and
    // `count` points to initialized writable storage.
    let status = unsafe {
        task_info(
            mach_task_self_,
            TASK_AUDIT_TOKEN,
            token.as_mut_ptr().cast::<i32>(),
            &mut count,
        )
    };
    if status != 0 || count != AUDIT_TOKEN_WORDS {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    let mut bytes = [0_u8; 32];
    for (index, word) in token.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    Ok(bytes)
}

pub(crate) fn launch_activate_socket_v2(
    name: &CStr,
) -> Result<Vec<OwnedFd>, NativeIdentityErrorV2> {
    let mut descriptors = ptr::null_mut();
    let mut count = 0_usize;
    // SAFETY: `name` is NUL terminated; both output pointers address
    // initialized writable storage. launchd allocates the returned array and
    // transfers every descriptor in it to this process on success.
    let status = unsafe { launch_activate_socket(name.as_ptr(), &mut descriptors, &mut count) };
    if status != 0 {
        return Err(NativeIdentityErrorV2::Io);
    }
    if descriptors.is_null() {
        return if count == 0 {
            Ok(Vec::new())
        } else {
            Err(NativeIdentityErrorV2::InvalidMeasurement)
        };
    }
    // SAFETY: successful launch activation returned an allocation containing
    // exactly `count` file descriptors. Copy them before releasing the array.
    let raw_descriptors = unsafe { std::slice::from_raw_parts(descriptors, count) }.to_vec();
    // SAFETY: launch_activate_socket documents that the caller owns this
    // allocation and must release it with free(3), including a zero-count
    // allocation.
    unsafe { nix::libc::free(descriptors.cast()) };

    let mut unique = BTreeSet::new();
    let valid = raw_descriptors
        .iter()
        .all(|descriptor| *descriptor >= 0 && unique.insert(*descriptor));
    if !valid {
        for descriptor in unique {
            let _ = nix::unistd::close(descriptor);
        }
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }

    Ok(raw_descriptors
        .into_iter()
        .map(|descriptor| {
            // SAFETY: launchd transferred one unique live descriptor and no
            // Rust owner was constructed before this exact conversion.
            unsafe { OwnedFd::from_raw_fd(descriptor) }
        })
        .collect())
}

pub(crate) fn socket_is_listening_v2(descriptor: i32) -> Result<bool, NativeIdentityErrorV2> {
    if descriptor < 0 {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let mut buffer = SocketFdInfoBufferV2([0_u8; PROC_PIDFDSOCKETINFO_SIZE]);
    let buffer_size = i32::try_from(buffer.0.len()).map_err(|_| NativeIdentityErrorV2::Io)?;
    // SAFETY: the buffer is writable, correctly aligned for the documented
    // socket_fdinfo layout, and its exact byte capacity is passed to libproc.
    // The call inspects a descriptor in this process and does not mutate it.
    let written = unsafe {
        nix::libc::proc_pidfdinfo(
            nix::libc::getpid(),
            descriptor,
            PROC_PIDFDSOCKETINFO,
            buffer.0.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    let options_end = offset_of!(SocketFdInfoPrefixV2, socket)
        + offset_of!(SocketInfoPrefixV2, options)
        + size_of::<i16>();
    if written < i32::try_from(options_end).map_err(|_| NativeIdentityErrorV2::Io)? {
        return Err(NativeIdentityErrorV2::Io);
    }
    // SAFETY: libproc initialized at least through the options field, the
    // backing buffer has eight-byte alignment, and the Rust prefix layout is
    // compile-time checked against Apple's public C layout.
    let information = unsafe { &*buffer.0.as_ptr().cast::<SocketFdInfoPrefixV2>() };
    Ok(information.socket.socket_type == nix::libc::SOCK_STREAM
        && (i32::from(information.socket.options) & nix::libc::SO_ACCEPTCONN) != 0)
}

pub(super) fn copy_code_identity_v2(
    audit_token: [u8; 32],
) -> Result<OwnedMacOsCodeIdentityV2, NativeIdentityErrorV2> {
    // SAFETY: CFDataCreate copies the entire fixed-size token before returning.
    let audit_data = OwnedCf::new(unsafe {
        CFDataCreate(
            ptr::null(),
            audit_token.as_ptr(),
            audit_token.len() as CFIndex,
        )
    })?;

    // SAFETY: the imported Security constant is a valid immortal CFString.
    let audit_key = unsafe { kSecGuestAttributeAudit };
    if audit_key.is_null() {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    let keys = [audit_key];
    let values = [audit_data.as_type()];
    // SAFETY: both one-element arrays remain live through the call. Null
    // callbacks are intentional because the exact immortal key and held value
    // need only remain valid until SecCodeCopyGuestWithAttributes returns.
    let attributes = OwnedCf::new(unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            ptr::null(),
            ptr::null(),
        )
    })?;

    let mut guest: SecCodeRef = ptr::null();
    // SAFETY: `attributes` is a valid CFDictionary containing the audit-token
    // CFData. On success Security returns one retained SecCode in `guest`.
    let guest_status = unsafe {
        SecCodeCopyGuestWithAttributes(
            ptr::null(),
            attributes.as_type(),
            K_SEC_CS_DEFAULT_FLAGS,
            &mut guest,
        )
    };
    if guest_status != ERR_SEC_SUCCESS {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    let guest = OwnedCf::new(guest)?;

    // SAFETY: `guest` is a live SecCode and a null requirement requests the
    // code's own validity. No output pointers are involved.
    let validity_status =
        unsafe { SecCodeCheckValidity(guest.as_type(), K_SEC_CS_DEFAULT_FLAGS, ptr::null()) };
    if validity_status != ERR_SEC_SUCCESS {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }

    let mut information: CFDictionaryRef = ptr::null();
    // SAFETY: `guest` may be passed where SecStaticCodeRef is accepted by this
    // API. On success `information` receives exactly one retained dictionary.
    let information_status = unsafe {
        SecCodeCopySigningInformation(
            guest.as_type(),
            K_SEC_CS_SIGNING_INFORMATION | K_SEC_CS_REQUIREMENT_INFORMATION,
            &mut information,
        )
    };
    if information_status != ERR_SEC_SUCCESS {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    let information = OwnedCf::new(information)?;

    let bundle_id = copy_required_string(
        information.as_type(),
        // SAFETY: imported Security constants are immortal CFString objects.
        unsafe { kSecCodeInfoIdentifier },
    )?;
    let team_id = copy_required_string(
        information.as_type(),
        // SAFETY: imported Security constants are immortal CFString objects.
        unsafe { kSecCodeInfoTeamIdentifier },
    )?;
    let code_directory = copy_required_data(
        information.as_type(),
        // SAFETY: imported Security constants are immortal CFString objects.
        unsafe { kSecCodeInfoUnique },
        MAX_CODE_DIRECTORY_BYTES,
    )?;
    let designated_requirement = copy_required_requirement(
        information.as_type(),
        // SAFETY: imported Security constants are immortal CFString objects.
        unsafe { kSecCodeInfoDesignatedRequirement },
    )?;
    // The entire signed entitlement blob is the closed projection: adding,
    // removing, or changing any entitlement changes the manifest-locked hash.
    let entitlements = copy_optional_data(
        information.as_type(),
        // SAFETY: imported Security constants are immortal CFString objects.
        unsafe { kSecCodeInfoEntitlements },
        MAX_ENTITLEMENT_BYTES,
    )?
    .unwrap_or_default();

    Ok(OwnedMacOsCodeIdentityV2 {
        bundle_id,
        team_id,
        code_directory,
        designated_requirement,
        entitlements,
    })
}

fn dictionary_value(
    dictionary: CFDictionaryRef,
    key: CFStringRef,
) -> Result<CFTypeRef, NativeIdentityErrorV2> {
    if dictionary.is_null() || key.is_null() {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: both arguments are live CoreFoundation objects; the returned
    // value is borrowed from `dictionary` and never released independently.
    let value = unsafe { CFDictionaryGetValue(dictionary, key) };
    if value.is_null() {
        Err(NativeIdentityErrorV2::CodeIdentityUnavailable)
    } else {
        Ok(value)
    }
}

fn copy_required_string(
    dictionary: CFDictionaryRef,
    key: CFStringRef,
) -> Result<String, NativeIdentityErrorV2> {
    let value = dictionary_value(dictionary, key)?;
    // SAFETY: CFGetTypeID accepts every non-null CF object.
    if unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    let mut buffer = [0_i8; MAX_IDENTITY_UTF8_BYTES + 1];
    // SAFETY: type was checked as CFString; the buffer is writable for its
    // declared length and CFStringGetCString always NUL-terminates on success.
    let copied = unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer.len() as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
        )
    };
    if copied == 0 {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: successful CFStringGetCString wrote a NUL-terminated string into
    // `buffer`; it cannot outlive this function because it is copied below.
    let bytes = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_bytes();
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| NativeIdentityErrorV2::CodeIdentityUnavailable)
}

fn copy_required_data(
    dictionary: CFDictionaryRef,
    key: CFStringRef,
    maximum: usize,
) -> Result<Vec<u8>, NativeIdentityErrorV2> {
    copy_optional_data(dictionary, key, maximum)?
        .filter(|bytes| !bytes.is_empty())
        .ok_or(NativeIdentityErrorV2::CodeIdentityUnavailable)
}

fn copy_optional_data(
    dictionary: CFDictionaryRef,
    key: CFStringRef,
    maximum: usize,
) -> Result<Option<Vec<u8>>, NativeIdentityErrorV2> {
    if dictionary.is_null() || key.is_null() {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: both arguments are live CoreFoundation objects.
    let value = unsafe { CFDictionaryGetValue(dictionary, key) };
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: CFGetTypeID accepts every non-null CF object.
    if unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: type was checked as CFData.
    let length = unsafe { CFDataGetLength(value) };
    let length =
        usize::try_from(length).map_err(|_| NativeIdentityErrorV2::CodeIdentityUnavailable)?;
    if length > maximum {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    if length == 0 {
        return Ok(Some(Vec::new()));
    }
    // SAFETY: type was checked as CFData and nonzero length requires a valid
    // immutable byte range for the lifetime of the containing dictionary.
    let bytes = unsafe { CFDataGetBytePtr(value) };
    if bytes.is_null() {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: `bytes` addresses exactly `length` immutable bytes, which are
    // copied into owned Rust storage before the dictionary can be released.
    Ok(Some(unsafe {
        std::slice::from_raw_parts(bytes, length).to_vec()
    }))
}

fn copy_required_requirement(
    dictionary: CFDictionaryRef,
    key: CFStringRef,
) -> Result<Vec<u8>, NativeIdentityErrorV2> {
    let requirement = dictionary_value(dictionary, key)?;
    // SAFETY: CFGetTypeID accepts every non-null CF object.
    if unsafe { CFGetTypeID(requirement) } != unsafe { SecRequirementGetTypeID() } {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    let mut data: CFDataRef = ptr::null();
    // SAFETY: the borrowed value was type-checked as SecRequirement; on success
    // `data` receives exactly one retained CFData.
    let status = unsafe { SecRequirementCopyData(requirement, K_SEC_CS_DEFAULT_FLAGS, &mut data) };
    if status != ERR_SEC_SUCCESS {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    let data = OwnedCf::new(data)?;
    copy_cf_data(data.as_type(), MAX_REQUIREMENT_BYTES)
}

fn copy_cf_data(data: CFDataRef, maximum: usize) -> Result<Vec<u8>, NativeIdentityErrorV2> {
    // SAFETY: caller passes a live type-checked CFData object.
    let length = unsafe { CFDataGetLength(data) };
    let length =
        usize::try_from(length).map_err(|_| NativeIdentityErrorV2::CodeIdentityUnavailable)?;
    if length == 0 || length > maximum {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: nonempty CFData has a valid immutable byte pointer.
    let bytes = unsafe { CFDataGetBytePtr(data) };
    if bytes.is_null() {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: `bytes` points to `length` bytes owned by `data`; copy completes
    // before the owning wrapper is released.
    Ok(unsafe { std::slice::from_raw_parts(bytes, length).to_vec() })
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(value: CFTypeRef);
    fn CFGetTypeID(value: CFTypeRef) -> CFTypeId;
    fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    fn CFDataGetTypeID() -> CFTypeId;
    fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    fn CFDictionaryCreate(
        allocator: CFAllocatorRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
    fn CFDictionaryGetValue(dictionary: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
    fn CFStringGetTypeID() -> CFTypeId;
    fn CFStringGetCString(
        string: CFStringRef,
        buffer: *mut c_char,
        buffer_size: CFIndex,
        encoding: u32,
    ) -> u8;
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecGuestAttributeAudit: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoDesignatedRequirement: CFStringRef;
    static kSecCodeInfoEntitlements: CFStringRef;

    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> i32;
    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: SecRequirementRef) -> i32;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    fn SecRequirementGetTypeID() -> CFTypeId;
    fn SecRequirementCopyData(
        requirement: SecRequirementRef,
        flags: u32,
        data: *mut CFDataRef,
    ) -> i32;
}

#[link(name = "System")]
extern "C" {
    static mach_task_self_: u32;
    fn launch_activate_socket(name: *const c_char, fds: *mut *mut i32, count: *mut usize) -> i32;
    fn task_info(
        target_task: u32,
        flavor: i32,
        task_info_out: *mut i32,
        task_info_out_count: *mut u32,
    ) -> i32;
}
