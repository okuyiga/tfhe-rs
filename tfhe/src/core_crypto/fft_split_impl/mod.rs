pub mod crypto;
pub mod math;

/// Splits a slice into chunks of equal size (known at compile time).
///
/// Returns the chunks and the remaining section of the input slice.
#[inline(always)]
pub fn as_arrays<const N: usize, T>(slice: &[T]) -> (&[[T; N]], &[T]) {
    let n = slice.len();
    let mid_div_n = n / N;
    let mid = mid_div_n * N;
    let ptr = slice.as_ptr();
    unsafe {
        (
            core::slice::from_raw_parts(ptr as *const [T; N], mid_div_n),
            core::slice::from_raw_parts(ptr.add(mid), n - mid),
        )
    }
}

/// Splits a slice into chunks of equal size (known at compile time).
///
/// Returns the chunks and the remaining section of the input slice.
#[inline(always)]
pub fn as_arrays_mut<const N: usize, T>(slice: &mut [T]) -> (&mut [[T; N]], &mut [T]) {
    let n = slice.len();
    let mid_div_n = n / N;
    let mid = mid_div_n * N;
    let ptr = slice.as_mut_ptr();
    unsafe {
        (
            core::slice::from_raw_parts_mut(ptr as *mut [T; N], mid_div_n),
            core::slice::from_raw_parts_mut(ptr.add(mid), n - mid),
        )
    }
}
