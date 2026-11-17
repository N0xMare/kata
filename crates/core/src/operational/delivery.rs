//! Derive resumable client delivery from global operational authority order.
//!
//! The workflow-owned producer supplies one Publish/FoldOnly/NoWire disposition
//! for every adjacent source transition. This module atomically commits delivery
//! rows, source progress and delivery high-water; it does not interpret authority
//! payloads or authenticate mapper provenance.
//!
//! Authority sequence and delivery sequence are distinct. Delivery reservations
//! may leave holes, but a sequence already published must never be reclaimed.
//! Reopen therefore requires the retained cursor/high-water even if all event rows
//! were pruned. Only a newly initialized empty store may create that metadata.
//!
//! One runtime owns one projector/allocator under the data-directory lock. This
//! is not a multi-process allocation protocol. Event bytes are rebuildable from
//! source facts; the same-identity cursor promise is not permission to delete its
//! high-water or reset source progress. A fresh-identity clone is a separate
//! operation and must reset client cursors explicitly.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kata_types::error::{KataError, KataResult};
use kata_types::event::Event;
use rusqlite::OptionalExtension;
use ulid::Ulid;

use crate::durable_event_log::DurableEventLog;

/// One frame to publish on the delivery plane, derived from ONE committed
/// authority transition.
///
/// The projector owns sequence allocation, cursor durability, and crash-safe
/// catch-up. It does NOT own the envelope: what a transition means to an SSE
/// client depends on attempt facts (`attempts.assignment_json`, the terminal
/// transition's payload) that the operational layer holds as opaque blobs by
/// design, and decoding them here would couple the planes. The workflow layer
/// supplies the mapping; this supplies the regime.
#[derive(Clone, Debug)]
pub struct DeliveryFrame {
    /// The AUTHORITY transition sequence this frame is derived from. Used only as
    /// a projection cursor — never as, and never compared to, a delivery
    /// sequence.
    pub source_seq: i64,
    /// The execution this frame belongs to; the runner's fold names it in a
    /// refusal. It is not stored on the delivery row.
    pub execution_id: Ulid,
    /// The envelope the delivery plane stores after replacing its zero sequence
    /// sentinel with the allocated delivery sequence. Its remaining fields must
    /// be the shape the SSE reader decodes, or the relay will skip it as corrupt.
    pub event: Event,
}

/// What the delivery projection does with one contiguous authority transition.
///
/// Every source transition has exactly one disposition. `FoldOnly` and `NoWire`
/// write no delivery row, but they are still consumed by the global source cursor;
/// omitting either from a batch would leave a gap that the projector refuses.
#[derive(Clone, Debug)]
pub enum DeliveryDisposition {
    /// Publish one client-visible delivery envelope.
    Publish(DeliveryFrame),
    /// The transition is consumed by a deciding fold but has no delivery shape.
    FoldOnly {
        /// The authority transition sequence being consumed.
        source_seq: i64,
    },
    /// The mapper classified this transition as producing no delivery envelope.
    NoWire {
        /// The authority transition sequence being consumed.
        source_seq: i64,
    },
}

impl DeliveryDisposition {
    /// The authority sequence consumed by this disposition.
    #[must_use]
    pub const fn source_seq(&self) -> i64 {
        match self {
            Self::Publish(frame) => frame.source_seq,
            Self::FoldOnly { source_seq } | Self::NoWire { source_seq } => *source_seq,
        }
    }
}

/// The delivery-plane cursor row: how far the projector has consumed the
/// authority chain, and the highest delivery sequence it has ever handed out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryCursor {
    /// Frames derived from an authority transition at or below this are already
    /// published.
    pub projected_through_source_seq: i64,
    /// The highest delivery sequence committed by the projector. Monotone
    /// across prunes, crashes and reopens; an uncommitted reservation does not
    /// appear here.
    pub delivery_high_water: u64,
}

/// Writes committed authority transitions onto the derived delivery plane.
pub struct DeliveryProjector {
    log: Arc<DurableEventLog>,
    /// Single-owner allocator, seeded only from the retained durable high-water.
    /// Reopen refuses missing metadata rather than inferring it from event rows.
    next_sequence: AtomicU64,
}

impl std::fmt::Debug for DeliveryProjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryProjector").finish_non_exhaustive()
    }
}

impl DeliveryProjector {
    /// Open the current delivery plane.
    ///
    /// # Invariant
    ///
    /// THIS PATH NEVER CREATES THE CURSOR. `delivery_projection_cursor` is part of the
    /// event log's stamped shape — created and seeded by the same
    /// transaction that stamps the version, and validated on every open — so a store
    /// that reaches here without it is DAMAGE and is refused. Lazy creation would
    /// make the stamp identify two shapes, and it could not be made safe by a
    /// "did this handle create the file" test: that is a property of the handle, so a genuinely
    /// damaged store opened by a process that happened to create the file would have
    /// had its non-reclaimed high-water reset to zero, which is the one number this
    /// plane must never rewind.
    ///
    /// A reopen therefore only READS, and must find both the source progress and the
    /// non-reclamation high-water intact even when retention emptied every event row.
    pub fn open(log: Arc<DurableEventLog>) -> KataResult<Self> {
        let conn = log.shared_conn();
        let conn = conn.lock();
        let present: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='delivery_projection_cursor')",
            [], |row| row.get(0),
        ).map_err(|error| KataError::Storage(format!("inspect delivery cursor: {error}")))?;
        if !present {
            return Err(KataError::Storage(
                "existing delivery store has no source cursor/high-water; refusing initialization"
                    .to_owned(),
            ));
        }
        let existing_head: i64 = conn
            .query_row("SELECT COALESCE(MAX(sequence), 0) FROM events", [], |row| {
                row.get(0)
            })
            .map_err(|error| KataError::Storage(format!("read delivery head: {error}")))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM delivery_projection_cursor",
                [],
                |row| row.get(0),
            )
            .map_err(|error| KataError::Storage(format!("count delivery cursor rows: {error}")))?;
        if count != 1 {
            return Err(KataError::Storage(format!(
                "delivery cursor requires one retained row, found {count}"
            )));
        }
        let cursor = read_cursor(&conn)?;
        let head = u64::try_from(existing_head)
            .map_err(|error| KataError::Storage(format!("invalid delivery head: {error}")))?;
        if cursor.delivery_high_water < head
            || (head > 0 && cursor.projected_through_source_seq == 0)
        {
            return Err(KataError::Storage(
                "delivery rows contradict the retained cursor/high-water".to_owned(),
            ));
        }
        drop(conn);
        Ok(Self {
            log,
            next_sequence: AtomicU64::new(cursor.delivery_high_water),
        })
    }

    /// Reserve the next delivery sequence. THE allocator for `events.sequence` —
    /// see the module's *ONE ALLOCATOR, TWO CALLERS*.
    ///
    /// # Invariant
    ///
    /// RESERVE, THEN INSERT. The value is consumed the moment it is
    /// handed out, whether or not the row at it ever commits, so a failed write
    /// leaves a permanent hole and no value is ever handed to two callers. Do NOT
    /// rewind it to "repair" a hole — that would risk re-issuing a live sequence,
    /// which is the one thing the delivery plane promises never to do.
    ///
    /// # Failure
    ///
    /// Refuses once the next value would exceed SQLite's signed `INTEGER` domain;
    /// no atomic state is changed and no negative SQL sequence is produced.
    pub(crate) fn reserve(&self) -> KataResult<u64> {
        let ceiling = u64::try_from(i64::MAX).expect("i64::MAX is representable as u64");
        let previous = self
            .next_sequence
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current < ceiling).then_some(current + 1)
            })
            .map_err(|_| {
                KataError::Storage(
                    "delivery sequence allocator is exhausted at SQLite i64::MAX".to_string(),
                )
            })?;
        Ok(previous + 1)
    }

    /// The highest delivery sequence this process has RESERVED, whether or not the
    /// row at it committed. `0` before anything is reserved on a fresh plane.
    ///
    /// This is the ALLOCATION counter, not the resumption bound: an aborted write
    /// leaves it one above a sequence no row exists at, which no client can have
    /// received. [`Self::delivery_head`] is what a resuming client is bounded by.
    pub(crate) fn reserved_head(&self) -> u64 {
        self.next_sequence.load(Ordering::SeqCst)
    }

    /// The durable cursor.
    pub fn cursor(&self) -> KataResult<DeliveryCursor> {
        let conn = self.log.shared_conn();
        let conn = conn.lock();
        read_cursor(&conn)
    }

    /// The delivery head SSE bounds `?since=` against: `MAX(sequence)` on the
    /// delivery plane.
    ///
    /// Deliberately the observed maximum rather than the high water: a client may
    /// only ask to resume from a value that IS on the plane, and a pruned log
    /// legitimately has a lower head than the counter. The high water governs
    /// ALLOCATION; the head governs RESUMPTION.
    pub fn delivery_head(&self) -> KataResult<u64> {
        self.log.latest_sequence()
    }

    /// Consume one contiguous batch of authority dispositions, publishing the
    /// dispositions that carry delivery frames.
    ///
    /// # Invariant
    ///
    /// ONE transaction: every row, the global source cursor, and the delivery high
    /// water commit together or not at all. The first disposition must be exactly
    /// `cursor + 1`, and every following disposition must be its adjacent global
    /// successor. Callers resume by reading the durable cursor; stale prefixes and
    /// source gaps are refused rather than silently filtered.
    ///
    /// Sequences come from [`Self::reserve`] — the plane's ONE allocator, shared
    /// with the live transition path — never from a second reading of the plane.
    /// A rolled-back batch therefore burns the sequences it reserved; that is the
    /// reserve-then-insert regime and the delivery contract is non-reclamation, not
    /// contiguity.
    ///
    /// Returns the delivery sequences allocated, in disposition order, for the
    /// dispositions that were published.
    ///
    /// # Failure
    ///
    /// Dispositions must begin at exactly `cursor + 1`, cover adjacent positive
    /// `source_seq` values, and leave a resumable cursor. Violations are typed
    /// refusals because accepting one would make an omitted transition invisible.
    pub fn project(&self, dispositions: &[DeliveryDisposition]) -> KataResult<Vec<u64>> {
        if dispositions.is_empty() {
            return Ok(Vec::new());
        }
        for disposition in dispositions {
            let source_seq = disposition.source_seq();
            if source_seq <= 0 {
                return Err(KataError::Validation(format!(
                    "delivery projector refuses a frame with non-positive source sequence {}; \
                     zero aliases 'no transition'",
                    source_seq
                )));
            }
            if source_seq == i64::MAX {
                return Err(KataError::Validation(
                    "delivery projector refuses source sequence i64::MAX because it cannot form \
                     a resumable cursor"
                        .to_string(),
                ));
            }
        }

        let conn = self.log.shared_conn();
        let mut conn = conn.lock();
        let tx = conn
            .transaction()
            .map_err(|error| KataError::Storage(format!("begin delivery projection: {error}")))?;
        let cursor = read_cursor(&tx)?;

        let mut expected = cursor
            .projected_through_source_seq
            .checked_add(1)
            .ok_or_else(|| {
                KataError::Validation(
                    "delivery projector source cursor is exhausted at i64::MAX".to_string(),
                )
            })?;
        for disposition in dispositions {
            let source_seq = disposition.source_seq();
            if source_seq != expected {
                return Err(KataError::Validation(format!(
                    "delivery projector requires a contiguous global authority batch beginning \
                     at cursor + 1 ({expected}), but received source sequence {source_seq}"
                )));
            }
            expected = source_seq + 1;
        }

        let mut allocated = Vec::new();
        // The last value RESERVED in this batch, or 0 when every disposition is
        // non-publishing. It is what the durable latch rises to, so a batch that
        // publishes nothing must not move it.
        let mut last_reserved = 0_u64;
        for disposition in dispositions {
            let DeliveryDisposition::Publish(frame) = disposition else {
                continue;
            };
            // THE allocator — not a second reading of `MAX(sequence)`, which is
            // blind to a reservation the live writer has not yet inserted.
            let sequence = self.reserve()?;
            let mut event = frame.event.clone();
            event.sequence = sequence;
            DurableEventLog::insert_event_row(&tx, &event, sequence)?;
            allocated.push(sequence);
            last_reserved = sequence;
        }

        let advanced_to = dispositions.last().map_or(
            cursor.projected_through_source_seq,
            DeliveryDisposition::source_seq,
        );
        tx.execute(
            "UPDATE delivery_projection_cursor
                SET projected_through_source_seq = ?1,
                    delivery_high_water = MAX(delivery_high_water, ?2)
              WHERE id = 0",
            rusqlite::params![
                advanced_to,
                i64::try_from(last_reserved).unwrap_or(i64::MAX)
            ],
        )
        .map_err(|error| KataError::Storage(format!("advance delivery cursor: {error}")))?;
        tx.commit()
            .map_err(|error| KataError::Storage(format!("commit delivery projection: {error}")))?;
        Ok(allocated)
    }
}

fn read_cursor(conn: &rusqlite::Connection) -> KataResult<DeliveryCursor> {
    conn.query_row(
        "SELECT projected_through_source_seq, delivery_high_water
           FROM delivery_projection_cursor WHERE id = 0",
        [],
        |row| {
            Ok(DeliveryCursor {
                projected_through_source_seq: row.get(0)?,
                delivery_high_water: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read delivery cursor: {error}")))?
    .ok_or_else(|| {
        KataError::Storage(
            "delivery projection cursor row is absent; the projector was not opened on this plane"
                .to_string(),
        )
    })
}
