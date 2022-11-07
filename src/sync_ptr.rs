use std::{
    convert::{AsMut, AsRef},
    fmt::{Display, Formatter, Result as FmtResult},
};

/// Mark a pointer as being safe to share between threads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncPtr<T> {
    ptr: *mut T,
}

impl<T> SyncPtr<T> {
    /// Return the underlying pointer.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }
}

impl<T> AsRef<T> for SyncPtr<T> {
    /// Return the underlying reference.
    fn as_ref(&self) -> &T {
        // Safety: The pointer is guaranteed to be non-null by the constructor.
        unsafe { &*self.ptr }
    }
}

impl<T> AsMut<T> for SyncPtr<T> {
    /// Return the underlying mutable reference.
    fn as_mut(&mut self) -> &mut T {
        // Safety: The pointer is guaranteed to be non-null by the constructor.
        unsafe { &mut *self.ptr }
    }
}

unsafe impl<T> Send for SyncPtr<T> {}
unsafe impl<T> Sync for SyncPtr<T> {}

impl<T: Display> Display for SyncPtr<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.as_ref().fmt(f)
    }
}

impl<T> From<*mut T> for SyncPtr<T> {
    fn from(ptr: *mut T) -> Self {
        if ptr.is_null() {
            panic!("Attempted to create a SyncPtr from a null pointer");
        }

        // We should also check that the pointer is aligned, but we can't do that until
        // pointer.is_aligned() is stabilized: https://github.com/rust-lang/rust/issues/96284

        Self {
            ptr,
        }
    }
}

impl<T> From<SyncPtr<T>> for *mut T {
    fn from(sync_ptr: SyncPtr<T>) -> Self {
        sync_ptr.ptr
    }
}

impl<T> From<&SyncPtr<T>> for *mut T {
    fn from(sync_ptr: &SyncPtr<T>) -> Self {
        sync_ptr.ptr
    }
}
