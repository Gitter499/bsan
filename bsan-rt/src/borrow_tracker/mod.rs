use core::alloc::Allocator;
use core::cell::LazyCell;
use core::ffi::c_void;
use core::mem::replace;
use core::{mem, ptr};

use bsan_shared::{
    AccessKind, AccessRelatedness, Permission, ProtectorKind, RangeMap, RetagInfo, Size,
};
use spin::{Mutex, Once};
use tree::{AllocRange, Tree};

use crate::alloc::string::ToString;
use crate::borrow_tracker::errors::{BsanTreeError, BtOp, BtResult, TreeError};
use crate::borrow_tracker::tree::{ChildParams, LocationState};
use crate::diagnostics::AccessCause;
use crate::hooks::BsanAllocHooks;
use crate::span::Span;
use crate::{AllocId, AllocInfo, BorTag, FreeListAddrUnion, GlobalCtx, Provenance};

pub mod errors;
#[cfg_attr(not(test), no_std)]
pub mod tree;
pub mod unimap;

#[macro_use]
use crate::println;

#[derive(Debug)]
pub struct BorrowTracker<'a> {
    prov: &'a Provenance,
    ctx: &'a GlobalCtx,
    allocator: BsanAllocHooks,
    object_address: *const c_void,
    // We treat AllocInfo as mutable as it is vulnerable to data races.
    // Data races are not undefined behavior on our end, but may be undefined
    // if the compiler optimizes an immutable borrow
    alloc_info: *mut AllocInfo,
    tree_lock: &'a Mutex<Option<Tree<BsanAllocHooks>>>,
}

impl<'a> BorrowTracker<'a> {
    /// # Safety
    /// Takes in provenance pointer that is checked via debug_asserts
    pub unsafe fn new(
        prov: *const Provenance,
        ctx: &'a GlobalCtx,
        object_address: *const c_void,
    ) -> BtResult<Self> {
        // Get global allocator
        let allocator = ctx.allocator();

        // TODO: Validate provenance and return a "safe" reference
        debug_assert!(unsafe { prov.as_ref().is_some() });

        // We assert that the tree ptr exists in the alloc metadata (and that the alloc metadata exists)
        debug_assert!(unsafe { !((*prov).alloc_info).is_null() });

        let alloc_info_ptr = AllocInfo::get_raw(prov);

        let prov = unsafe { &*prov };

        if prov.alloc_id != unsafe { (*alloc_info_ptr).alloc_id } {
            return Err(errors::BorrowTrackerError::UseAfterFree(BtOp {
                op: errors::BtOpType::Unknown,
                // TODO: Pass in actual span/backtrace
                span: Some(Span::new()),
                reason: Some(format!(
                    "Allocation IDs don't match. Provenance AllocID: {:?}\nAllocInfo AllocID: {:?}",
                    prov.alloc_id,
                    unsafe { (*alloc_info_ptr).alloc_id }
                )),
            }));
        }

        let base_offset = unsafe { (*alloc_info_ptr).base_offset(object_address) };

        // Check for out of bounds accessess
        let lower_bound = unsafe { (*alloc_info_ptr).base_addr() as usize };
        let upper_bound = unsafe { lower_bound + (*alloc_info_ptr).size };
        // TODO: Checkout lib functions to compare pointers instead of using usize
        if (object_address as usize) < lower_bound || object_address as usize >= upper_bound {
            // TODO: Add proper error handling and bailing
            // Access out-of-bounds error
            return Err(errors::BorrowTrackerError::OutOfBounds(BtOp {
                op: errors::BtOpType::Unknown,
                // TODO: Pass in actual span/backtrace
                span: Some(Span::new()),
                reason: Some(
                    format!(
                        "Object address is outside of the allocation range.\nObject Address: {:?}\nLower Bound: {:?}\nUpper Bound: {:?}",
                        (object_address as usize),
                        lower_bound,
                        upper_bound
                    )
                )
            }));
        }

        // Cast the Tree void ptr into `Tree` by locking the Tree

        Ok(Self {
            prov,
            ctx,
            allocator,
            object_address,
            tree_lock: unsafe { &(*alloc_info_ptr).tree_lock },
            alloc_info: alloc_info_ptr,
        })
    }

    pub fn retag(&self, retag_info: &RetagInfo) -> BtResult<()> {
        // Tree is assumed to be  initialized
        let mut lock = self.tree_lock.lock();
        let tree = unsafe { lock.as_mut().unwrap_unchecked() };

        #[cfg(debug_assertions)]
        if tree.is_allocation_of(self.prov.bor_tag) {
            use crate::borrow_tracker::errors::BorrowTrackerError;

            return Err(BorrowTrackerError::ErroneousRetag(BtOp {
                op: errors::BtOpType::Retag,
                // TODO: Replace with actual span/retag
                span: Some(Span::new()),
                reason: Some("Tag exists in Tree indicating an erroneus retag".to_string()),
            }));
        }

        // TODO: Pass this in
        let mut perms_map = RangeMap::new_in(
            Size::from_bytes(unsafe { (*self.alloc_info).size }),
            LocationState::new_accessed(
                Permission::new_disabled(),
                bsan_shared::IdempotentForeignAccess::None,
            ),
            self.allocator,
        );

        let base_offset = unsafe { (*self.alloc_info).base_offset(self.object_address) };

        for (perm_range, perm) in perms_map.iter_mut_all() {
            if perm.is_accessed() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start
                let range_in_alloc = unsafe {
                    AllocRange {
                        start: Size::from_bytes(perm_range.start) + base_offset,
                        size: Size::from_bytes(perm_range.end - perm_range.start),
                    }
                };

                println!("{:?}", range_in_alloc);

                self.access(AccessKind::Read, range_in_alloc)?;
            }
        }

        #[allow(clippy::diverging_sub_expression)]
        let child_params: ChildParams = ChildParams {
            base_offset,
            parent_tag: self.prov.bor_tag,
            new_tag: self.ctx.new_bor_tag(),
            initial_perms: perms_map,
            default_perm: todo!("Implement default perm"),
            protected: todo!("Implement protected"),
            span: Span::new(),
        };

        tree.new_child(child_params);

        Ok(())
    }

    pub fn access(&self, access_kind: AccessKind, alloc_range: AllocRange) -> BtResult<()> {
        // Tree is initialized
        let mut lock = self.tree_lock.lock();
        let tree = unsafe { lock.as_mut().unwrap_unchecked() };
        // Perform the access (update the Tree Borrows FSM)
        // Uses a dummy span
        tree.perform_access(
            self.prov.bor_tag,
            // TODO: Validate the Range
            Some((alloc_range, access_kind, AccessCause::Explicit(access_kind))),
            self.ctx,
            self.prov.alloc_id,
            Span::new(),
            // Passing in allocator explicitly to stay consistent with API
            self.allocator,
        )?;

        Ok(())
    }

    pub fn dealloc(&mut self, object_address: *const c_void) -> BtResult<()> {
        // Tree is initialized
        let lock_addr_id = self.prov.alloc_id.get();
        let metadata_id = unsafe { (*self.alloc_info).alloc_id.get() };

        if lock_addr_id != metadata_id {
            return Err(errors::BorrowTrackerError::UseAfterFree(BtOp {
                op: errors::BtOpType::Dealloc,
                span: Some(Span::new()),
                reason: Some(
                    format!(
                        "Allocation ID in pointer metadata does not match the one in the lock address.\nLock address ID: {lock_addr_id:?}\nPointer metadata ID: {metadata_id:?}",
                    )),
            }));
        }

        let mut lock = self.tree_lock.lock();
        let tree = unsafe { lock.as_mut().unwrap_unchecked() };

        tree.dealloc(
            self.prov.bor_tag,
            unsafe {
                AllocRange {
                    start: (*self.alloc_info).base_offset(object_address),
                    size: Size::from_bytes((*self.alloc_info).size),
                }
            },
            self.ctx,
            self.prov.alloc_id,
            Span::new(),
            self.allocator,
        )?;

        // The default value of `AllocInfo` is zero-initialized,
        // automatically making all future accesses UB.
        unsafe { drop(ptr::replace(self.alloc_info, AllocInfo::default())) }

        unsafe { self.ctx.deallocate_lock_location(self.alloc_info) };
        Ok(())
    }
}
