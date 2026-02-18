//! Interface for syncing state between clients.

use core::convert::Infallible;

use buggy::Bug;
use rkyv::{
    Archived,
    bytecheck::{self, CheckBytes},
    niche::niched_option::NichedOption,
    rancor::ResultExt as _,
    traits::Portable,
    with::{ArchiveWith, DefaultNiche, MapNiche},
};

use crate::{
    Address, MaxCut, Prior,
    command::{CmdId, Command, Priority},
    rkyv_utils::{ArchivedBytes, Bytes},
};

/// Sync command constructed for serialization.
#[derive(Debug, rkyv::Archive, rkyv::Serialize)]
#[rkyv(as = ArchivedSyncCommand)]
#[rkyv(archive_bounds(
    MapNiche<Bytes>: ArchiveWith<Option<&'a [u8]>, Archived = NichedOption<ArchivedBytes, DefaultNiche>>,
    Bytes: ArchiveWith<&'a [u8], Archived = ArchivedBytes>,
))]
pub struct SyncCommand<'a> {
    pub(super) priority: Priority,
    pub(super) id: CmdId,
    pub(super) parent: Prior<Address>,
    #[rkyv(with = MapNiche<Bytes>)]
    pub(super) policy: Option<&'a [u8]>,
    #[rkyv(with = Bytes)]
    pub(super) data: &'a [u8],
    pub(super) max_cut: MaxCut,
}

/// An archived [`SyncCommand`].
///
/// Defined manually to remove lifetime parameter.
#[derive(CheckBytes, Portable)]
#[bytecheck(crate = bytecheck)]
#[repr(C)]
pub struct ArchivedSyncCommand {
    priority: Archived<Priority>,
    id: Archived<CmdId>,
    parent: Archived<Prior<Address>>,
    policy: NichedOption<ArchivedBytes, DefaultNiche>,
    data: ArchivedBytes,
    max_cut: Archived<MaxCut>,
}

impl<'a> Command for &'a ArchivedSyncCommand {
    fn priority(&self) -> Priority {
        rkyv::api::low::deserialize::<_, Infallible>(&self.priority).always_ok()
    }

    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        rkyv::api::low::deserialize::<_, Infallible>(&self.parent).always_ok()
    }

    fn policy(&self) -> Option<&'a [u8]> {
        self.policy.as_ref().map(ArchivedBytes::as_slice)
    }

    fn bytes(&self) -> &'a [u8] {
        self.data.as_slice()
    }

    fn max_cut(&self) -> Result<MaxCut, Bug> {
        Ok(rkyv::api::low::deserialize::<_, Infallible>(&self.max_cut).always_ok())
    }
}

unsafe impl crate::rkyv_utils::Adjust for ArchivedSyncCommand {
    unsafe fn adjust(&mut self, amount: rkyv::primitive::FixedIsize) {
        unsafe {
            self.policy.adjust(amount);
            self.data.adjust(amount);
        }
    }
}
