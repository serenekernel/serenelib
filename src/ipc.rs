extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::{align_of, size_of};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Handle(pub u64);

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IpcArray {
    pub offset: u32,
    pub element_count: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IpcBytes {
    pub offset: u32,
    pub len: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IpcPayloadError {
    OffsetOutOfBounds,
    LengthOutOfBounds,
    ArithmeticOverflow,
    Misaligned,
}

#[repr(C)]
pub struct IpcMessageHeader {
    pub length: u32,   
    pub sender_pid: u64,
    pub reply_handle: u64,
}

impl IpcMessageHeader {
    pub unsafe fn payload(&self) -> &[u8] {
        let payload_ptr = unsafe { (self as *const Self).add(1) as *const u8 };
        unsafe { core::slice::from_raw_parts(payload_ptr, self.length as usize) }
    }
    pub unsafe fn payload_mut(&mut self) -> &mut [u8] {
        let payload_ptr = unsafe { (self as *mut Self).add(1) as *mut u8 };
        unsafe { core::slice::from_raw_parts_mut(payload_ptr, self.length as usize) }
    }
}

pub struct IpcPayloadReader<'a> {
    payload: &'a [u8],
}

impl<'a> IpcPayloadReader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self { payload }
    }

    pub unsafe fn from_message(message: &'a IpcMessageHeader) -> Self {
        Self {
            payload: unsafe { message.payload() },
        }
    }

    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.payload
    }

    pub fn read_bytes(&self, bytes: IpcBytes) -> Result<&'a [u8], IpcPayloadError> {
        let start = bytes.offset as usize;
        let len = bytes.len as usize;
        let end = start
            .checked_add(len)
            .ok_or(IpcPayloadError::ArithmeticOverflow)?;

        if start > self.payload.len() {
            return Err(IpcPayloadError::OffsetOutOfBounds);
        }
        if end > self.payload.len() {
            return Err(IpcPayloadError::LengthOutOfBounds);
        }

        Ok(&self.payload[start..end])
    }

    pub fn read_array<T>(&self, array: IpcArray) -> Result<&'a [T], IpcPayloadError> {
        let start = array.offset as usize;
        let byte_len = (array.element_count as usize)
            .checked_mul(size_of::<T>())
            .ok_or(IpcPayloadError::ArithmeticOverflow)?;
        let end = start
            .checked_add(byte_len)
            .ok_or(IpcPayloadError::ArithmeticOverflow)?;

        if start > self.payload.len() {
            return Err(IpcPayloadError::OffsetOutOfBounds);
        }
        if end > self.payload.len() {
            return Err(IpcPayloadError::LengthOutOfBounds);
        }

        let ptr = unsafe { self.payload.as_ptr().add(start) };
        if (ptr as usize) % align_of::<T>() != 0 {
            return Err(IpcPayloadError::Misaligned);
        }

        Ok(unsafe { core::slice::from_raw_parts(ptr as *const T, array.element_count as usize) })
    }

    pub fn read_struct<T>(&self, offset: u32) -> Result<&'a T, IpcPayloadError> {
        let start = offset as usize;
        let end = start
            .checked_add(size_of::<T>())
            .ok_or(IpcPayloadError::ArithmeticOverflow)?;

        if start > self.payload.len() {
            return Err(IpcPayloadError::OffsetOutOfBounds);
        }
        if end > self.payload.len() {
            return Err(IpcPayloadError::LengthOutOfBounds);
        }

        let ptr = unsafe { self.payload.as_ptr().add(start) };
        if (ptr as usize) % align_of::<T>() != 0 {
            return Err(IpcPayloadError::Misaligned);
        }

        Ok(unsafe { &*(ptr as *const T) })
    }
}

pub struct IpcPayloadBuilder {
    payload: Vec<u8>,
}

impl IpcPayloadBuilder {
    pub fn with_fixed_size(fixed_size: usize) -> Self {
        Self {
            payload: vec![0u8; fixed_size],
        }
    }

    pub fn from_fixed_bytes(fixed: &[u8]) -> Self {
        Self {
            payload: fixed.to_vec(),
        }
    }

    pub fn fixed_mut(&mut self) -> &mut [u8] {
        self.payload.as_mut_slice()
    }

    pub fn write_struct<T>(&mut self, offset: u32, value: &T) -> Result<(), IpcPayloadError> {
        let start = offset as usize;
        let len = size_of::<T>();
        let end = start
            .checked_add(len)
            .ok_or(IpcPayloadError::ArithmeticOverflow)?;

        if start > self.payload.len() {
            return Err(IpcPayloadError::OffsetOutOfBounds);
        }
        if end > self.payload.len() {
            return Err(IpcPayloadError::LengthOutOfBounds);
        }

        let bytes = unsafe { core::slice::from_raw_parts((value as *const T) as *const u8, len) };
        self.payload[start..end].copy_from_slice(bytes);
        Ok(())
    }

    pub fn push_bytes(&mut self, data: &[u8]) -> Result<IpcBytes, IpcPayloadError> {
        let offset = u32::try_from(self.payload.len()).map_err(|_| IpcPayloadError::ArithmeticOverflow)?;
        let len = u32::try_from(data.len()).map_err(|_| IpcPayloadError::ArithmeticOverflow)?;
        self.payload.extend_from_slice(data);
        Ok(IpcBytes { offset, len })
    }

    pub fn push_array<T: Copy>(&mut self, data: &[T]) -> Result<IpcArray, IpcPayloadError> {
        let align = align_of::<T>();
        if align > 1 {
            let new_len = align_up(self.payload.len(), align).ok_or(IpcPayloadError::ArithmeticOverflow)?;
            if new_len > self.payload.len() {
                self.payload.resize(new_len, 0);
            }
        }

        let offset = u32::try_from(self.payload.len()).map_err(|_| IpcPayloadError::ArithmeticOverflow)?;
        let element_count = u32::try_from(data.len()).map_err(|_| IpcPayloadError::ArithmeticOverflow)?;

        let byte_len = data
            .len()
            .checked_mul(size_of::<T>())
            .ok_or(IpcPayloadError::ArithmeticOverflow)?;
        let bytes = unsafe { core::slice::from_raw_parts(data.as_ptr() as *const u8, byte_len) };
        self.payload.extend_from_slice(bytes);

        Ok(IpcArray {
            offset,
            element_count,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.payload.as_slice()
    }

    pub fn finish(self) -> Vec<u8> {
        self.payload
    }
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|v| v & !mask)
}
