//! Turning a caller's `limit`/`offset` into a page this node will serve.
//!
//! One function, [`page_of`], stands between every paginated registry read and
//! the store beneath it, so the three decisions below are made once rather than
//! twenty-odd times:
//!
//! 1. **Absent means the default, not everything.** A caller who passes no
//!    pagination argument at all — every caller written before this existed —
//!    gets [`RPC_PAGE_DEFAULT`] rows. That is a valid, useful answer; it is
//!    simply no longer an answer whose size the chain's writers choose.
//! 2. **Above the maximum is refused, not clamped.** See
//!    [`RpcError::PageOutOfBounds`]. A clamp would hand back a truncated list
//!    that is byte-for-byte indistinguishable from a complete one.
//! 3. **Zero is a legal page.** `limit = 0` returns an empty list rather than
//!    an error: it is a well-defined request ("nothing, please") and a caller
//!    probing reachability should not have to send a row to do it.
//!
//! These readers sit outside consensus, so none of this is gated on an
//! activation height and none of it can make two nodes disagree about a block.
//! See `sumchain_storage::page` for the same argument from the store side.

use sumchain_storage::{PageSpec, PAGE_DEFAULT, PAGE_MAX, PAGE_OFFSET_MAX};

use crate::RpcError;

/// Page size served when the caller names none.
pub const RPC_PAGE_DEFAULT: u32 = PAGE_DEFAULT as u32;

/// Largest page any caller may ask for. Above this is `-32004`, not a clamp.
pub const RPC_PAGE_MAX: u32 = PAGE_MAX as u32;

/// Furthest into a family any caller may page. Above this is `-32004`.
pub const RPC_PAGE_OFFSET_MAX: u32 = PAGE_OFFSET_MAX as u32;

/// Resolve caller-supplied `limit` and `offset` into a bounded [`PageSpec`].
///
/// `method` names the caller in the refusal, so an operator reading a log can
/// tell which of the registry reads was asked for too much.
pub fn page_of(
    method: &str,
    limit: Option<u32>,
    offset: Option<u32>,
) -> std::result::Result<PageSpec, RpcError> {
    let limit = limit.unwrap_or(RPC_PAGE_DEFAULT);
    let offset = offset.unwrap_or(0);

    if limit > RPC_PAGE_MAX {
        return Err(RpcError::PageOutOfBounds(format!(
            "{}: limit {} exceeds the maximum page of {}; ask for {} or fewer rows and page with \
             offset. This node refuses rather than truncating, so that a short answer always \
             means there is no more to say.",
            method, limit, RPC_PAGE_MAX, RPC_PAGE_MAX
        )));
    }
    if offset > RPC_PAGE_OFFSET_MAX {
        return Err(RpcError::PageOutOfBounds(format!(
            "{}: offset {} exceeds the maximum of {}; this node will not walk further into a \
             column family than that for one request.",
            method, offset, RPC_PAGE_OFFSET_MAX
        )));
    }

    Ok(PageSpec::new(offset as usize, limit as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_arguments_resolve_to_the_bounded_default() {
        let page = page_of("m", None, None).expect("default page");
        assert_eq!(page.offset(), 0);
        assert_eq!(page.limit(), RPC_PAGE_DEFAULT as usize);
    }

    #[test]
    fn a_limit_above_the_maximum_is_refused_rather_than_clamped() {
        let err = page_of("m", Some(RPC_PAGE_MAX + 1), None).expect_err("must refuse");
        let obj: jsonrpsee::types::ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), -32004);
    }

    #[test]
    fn an_offset_above_the_maximum_is_refused_rather_than_clamped() {
        let err = page_of("m", None, Some(RPC_PAGE_OFFSET_MAX + 1)).expect_err("must refuse");
        let obj: jsonrpsee::types::ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), -32004);
    }

    #[test]
    fn the_maximum_page_itself_is_accepted() {
        let page = page_of("m", Some(RPC_PAGE_MAX), Some(RPC_PAGE_OFFSET_MAX)).expect("at bound");
        assert_eq!(page.limit(), RPC_PAGE_MAX as usize);
        assert_eq!(page.offset(), RPC_PAGE_OFFSET_MAX as usize);
    }

    #[test]
    fn a_zero_limit_is_an_empty_page_and_not_an_error() {
        let page = page_of("m", Some(0), None).expect("zero is legal");
        assert_eq!(page.limit(), 0);
    }
}
