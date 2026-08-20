//! Flow-entry instructions (`ofp_instruction_*`, §7.2.5).
//!
//! An instruction is what a flow entry *does* when it matches; actions
//! ([`crate::protocol::action`]) are what an instruction carries.
//! [`Instruction::apply_actions`] is the common one -- it runs its actions
//! immediately, rather than deferring them to the action set.

use crate::protocol::action::parse_actions;
use crate::protocol::action::Action;
use crate::protocol::bytes::{checked_u16_len, read_u16, read_u32, read_u64};
use crate::protocol::constants::{
    OFPIT_APPLY_ACTIONS, OFPIT_CLEAR_ACTIONS, OFPIT_EXPERIMENTER, OFPIT_GOTO_TABLE,
    OFPIT_STAT_TRIGGER, OFPIT_WRITE_ACTIONS, OFPIT_WRITE_METADATA,
};
use crate::protocol::error::{OfError, Result};

#[allow(clippy::unnecessary_wraps)]
const fn ensure_zero_padding(_buf: &[u8]) -> Result<()> {
    // Section 7.1.2 requires recipients to ignore padding contents.
    Ok(())
}

fn pad_to_8(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

fn invalid_len(len: usize) -> OfError {
    OfError::InvalidLength(u16::try_from(len).unwrap_or(u16::MAX))
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// One instruction of a flow entry.
///
/// ```
/// use openflow::protocol::action::Action;
/// use openflow::protocol::instruction::Instruction;
///
/// // Send matching packets out port 2, then continue in table 1.
/// let instructions = vec![
///     Instruction::apply_actions(vec![Action::output(2)]),
///     Instruction::GotoTable(1),
/// ];
/// assert_eq!(instructions.len(), 2);
/// ```
pub enum Instruction {
    /// `OFPIT_GOTO_TABLE`: continue processing in the given table, which
    /// must be numerically greater than the current one.
    GotoTable(u8),
    /// `OFPIT_WRITE_METADATA`: write masked bits into the metadata field
    /// carried between tables.
    WriteMetadata {
        /// Value to write.
        metadata: u64,
        /// Which bits of `metadata` to write; zero bits are left alone.
        metadata_mask: u64,
    },
    /// `OFPIT_WRITE_ACTIONS`: merge these actions into the action set,
    /// applied only when the pipeline ends.
    WriteActions(Vec<Action>),
    /// `OFPIT_APPLY_ACTIONS`: apply these actions immediately, in order,
    /// before any further table processing.
    ApplyActions(Vec<Action>),
    /// `OFPIT_CLEAR_ACTIONS`: empty the action set.
    ClearActions,
    /// `OFPIT_STAT_TRIGGER`: report flow statistics once a threshold is
    /// crossed.
    StatTrigger {
        /// `OFPSTF_*` flags: whether thresholds are periodic, and whether
        /// only the first is reported.
        flags: u32,
        /// The `ofp_stats` threshold list that fires this trigger.
        thresholds: Vec<crate::protocol::oxs::Tlv>,
    },
    /// `OFPIT_EXPERIMENTER`: a vendor instruction, uninterpreted.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor payload.
        data: Vec<u8>,
    },
    /// An instruction type this crate does not implement (`OFPIT_DEPRECATED`
    /// among them), kept verbatim so it round-trips.
    Unknown {
        /// The `OFPIT_*` type from the wire.
        instruction_type: u16,
        /// Body bytes following the 4-byte instruction header.
        data: Vec<u8>,
    },
}

impl Instruction {
    /// An `OFPIT_APPLY_ACTIONS` instruction carrying `actions`.
    #[must_use]
    pub const fn apply_actions(actions: Vec<Action>) -> Self {
        Self::ApplyActions(actions)
    }

    /// Append this instruction's wire encoding to `out`, 8-byte aligned.
    /// # Errors
    ///
    /// Returns an error if an action list, stats list, or instruction length
    /// overflows a wire `u16` length field.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut encoded = Vec::new();
        self.encode_into(&mut encoded)?;
        out.extend_from_slice(&encoded);
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::GotoTable(table_id) => {
                out.extend_from_slice(&OFPIT_GOTO_TABLE.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                out.push(*table_id);
                out.extend_from_slice(&[0u8; 3]);
            }
            Self::WriteMetadata {
                metadata,
                metadata_mask,
            } => {
                out.extend_from_slice(&OFPIT_WRITE_METADATA.to_be_bytes());
                out.extend_from_slice(&24u16.to_be_bytes());
                out.extend_from_slice(&[0u8; 4]);
                out.extend_from_slice(&metadata.to_be_bytes());
                out.extend_from_slice(&metadata_mask.to_be_bytes());
            }
            Self::WriteActions(actions) => {
                encode_actions_instruction(out, OFPIT_WRITE_ACTIONS, actions)?;
            }
            Self::ApplyActions(actions) => {
                encode_actions_instruction(out, OFPIT_APPLY_ACTIONS, actions)?;
            }
            Self::ClearActions => {
                out.extend_from_slice(&OFPIT_CLEAR_ACTIONS.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&[0u8; 4]);
            }
            Self::StatTrigger { flags, thresholds } => {
                let start = out.len();
                out.extend_from_slice(&OFPIT_STAT_TRIGGER.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&flags.to_be_bytes());
                crate::protocol::oxs::encode_stats(out, thresholds)?;
                pad_to_8(out);
                let len = checked_u16_len(out.len() - start)?;
                out.get_mut(start + 2..start + 4)
                    .ok_or(OfError::ShortBuffer)?
                    .copy_from_slice(&len.to_be_bytes());
            }
            Self::Experimenter { experimenter, data } => {
                let start = out.len();
                out.extend_from_slice(&OFPIT_EXPERIMENTER.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(data);
                pad_to_8(out);
                let len = checked_u16_len(out.len() - start)?;
                out.get_mut(start + 2..start + 4)
                    .ok_or(OfError::ShortBuffer)?
                    .copy_from_slice(&len.to_be_bytes());
            }
            Self::Unknown {
                instruction_type,
                data,
            } => {
                let start = out.len();
                out.extend_from_slice(&instruction_type.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(data);
                pad_to_8(out);
                let len = checked_u16_len(out.len() - start)?;
                out.get_mut(start + 2..start + 4)
                    .ok_or(OfError::ShortBuffer)?
                    .copy_from_slice(&len.to_be_bytes());
            }
        }
        Ok(())
    }
}

fn encode_actions_instruction(
    out: &mut Vec<u8>,
    instruction_type: u16,
    actions: &[Action],
) -> Result<()> {
    let start = out.len();

    out.extend_from_slice(&instruction_type.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);

    for action in actions {
        action.encode(out)?;
    }

    let len = checked_u16_len(out.len() - start)?;
    out.get_mut(start + 2..start + 4)
        .ok_or(OfError::ShortBuffer)?
        .copy_from_slice(&len.to_be_bytes());
    Ok(())
}

/// Parse a sequence of `OpenFlow` instructions.
///
/// # Errors
///
/// Returns an error if the buffer is truncated or contains an invalid
/// instruction.
pub fn parse_instructions(buf: &[u8]) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len() - offset < 4 {
            return Err(OfError::ShortBuffer);
        }
        let instruction_type = read_u16(buf, offset)?;
        let len = read_u16(buf, offset + 2)? as usize;
        if len < 4 || !len.is_multiple_of(8) {
            return Err(invalid_len(len));
        }
        if offset + len > buf.len() {
            return Err(OfError::ShortBuffer);
        }
        instructions.push(parse_instruction(
            instruction_type,
            buf.get(offset..offset + len).ok_or(OfError::ShortBuffer)?,
        )?);
        offset += len;
    }
    Ok(instructions)
}

fn parse_instruction(instruction_type: u16, raw: &[u8]) -> Result<Instruction> {
    match instruction_type {
        OFPIT_GOTO_TABLE => parse_goto_table(raw),
        OFPIT_WRITE_METADATA => parse_write_metadata(raw),
        OFPIT_WRITE_ACTIONS | OFPIT_APPLY_ACTIONS => {
            parse_actions_instruction(instruction_type, raw)
        }
        OFPIT_CLEAR_ACTIONS => parse_clear_actions(raw),
        OFPIT_STAT_TRIGGER => parse_stat_trigger(raw),
        OFPIT_EXPERIMENTER => parse_experimenter(raw),
        _ => Ok(Instruction::Unknown {
            instruction_type,
            data: raw.get(4..).ok_or(OfError::ShortBuffer)?.to_vec(),
        }),
    }
}

fn parse_goto_table(raw: &[u8]) -> Result<Instruction> {
    let fixed: &[u8; 8] = raw.try_into().map_err(|_| invalid_len(raw.len()))?;
    ensure_zero_padding(&fixed[5..8])?;
    Ok(Instruction::GotoTable(fixed[4]))
}

fn parse_write_metadata(raw: &[u8]) -> Result<Instruction> {
    if raw.len() != 24 {
        return Err(invalid_len(raw.len()));
    }
    let head: &[u8; 8] = raw
        .first_chunk::<8>()
        .ok_or_else(|| invalid_len(raw.len()))?;
    ensure_zero_padding(&head[4..8])?;
    Ok(Instruction::WriteMetadata {
        metadata: read_u64(raw, 8)?,
        metadata_mask: read_u64(raw, 16)?,
    })
}

fn parse_actions_instruction(instruction_type: u16, raw: &[u8]) -> Result<Instruction> {
    let head: &[u8; 8] = raw
        .first_chunk::<8>()
        .ok_or_else(|| invalid_len(raw.len()))?;
    ensure_zero_padding(&head[4..8])?;
    let actions = parse_actions(raw.get(8..).ok_or(OfError::ShortBuffer)?)?;
    Ok(if instruction_type == OFPIT_WRITE_ACTIONS {
        Instruction::WriteActions(actions)
    } else {
        Instruction::ApplyActions(actions)
    })
}

fn parse_clear_actions(raw: &[u8]) -> Result<Instruction> {
    let fixed: &[u8; 8] = raw.try_into().map_err(|_| invalid_len(raw.len()))?;
    ensure_zero_padding(&fixed[4..8])?;
    Ok(Instruction::ClearActions)
}

fn parse_stat_trigger(raw: &[u8]) -> Result<Instruction> {
    if raw.len() < 16 {
        return Err(invalid_len(raw.len()));
    }
    let (thresholds, stats_padded) = crate::protocol::oxs::parse_stats(raw, 8)?;
    if 8 + stats_padded != raw.len() {
        return Err(invalid_len(raw.len()));
    }
    Ok(Instruction::StatTrigger {
        flags: read_u32(raw, 4)?,
        thresholds,
    })
}

fn parse_experimenter(raw: &[u8]) -> Result<Instruction> {
    if raw.len() < 8 {
        return Err(invalid_len(raw.len()));
    }
    Ok(Instruction::Experimenter {
        experimenter: read_u32(raw, 4)?,
        data: raw.get(8..).ok_or(OfError::ShortBuffer)?.to_vec(),
    })
}
