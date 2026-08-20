//! Flow-table modification: `OFPT_FLOW_MOD` (`ofp_flow_mod`, §7.3.4).
//!
//! Two near-identical types live here, one per direction: [`Rule`] is what
//! you build and send, [`Entry`] is what a received flow-mod decodes into.
//! See `examples/02_add_flow.rs`.

use crate::protocol::bytes::{checked_u16_len, read_u16, read_u32, read_u64};
use crate::protocol::constants::{
    OFPFC_ADD, OFPFC_DELETE, OFPFC_DELETE_STRICT, OFPFC_MODIFY, OFPFC_MODIFY_STRICT, OFPG_ANY,
    OFPMT_OXM, OFPP_ANY, OFPT_FLOW_MOD, OFP_FLOW_PERMANENT, OFP_HEADER_LEN, OFP_NO_BUFFER,
    OFP_VERSION_1_5,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;
use crate::protocol::instruction::parse_instructions;
use crate::protocol::instruction::Instruction;
use crate::protocol::ofmatch::Match;
use crate::protocol::oxm;

#[derive(Debug, Clone)]
/// A flow-table modification to send to a switch: add, modify, or delete
/// a flow entry.
///
/// This is the **encode** side, with a typed [`Match`]. A flow-mod
/// *received* from the wire decodes into [`Entry`] instead, which keeps
/// its match as raw OXM bytes.
///
/// Build one with [`Rule::add`] or [`Rule::delete`] and adjust the fields
/// you need -- the constructors default to a permanent entry with no
/// cookie and no flags.
///
/// ```
/// use openflow::protocol::constants::{ETH_TYPE_IPV4, OFPFF_SEND_FLOW_REM};
/// use openflow::protocol::action::Action;
/// use openflow::protocol::instruction::Instruction;
/// use openflow::protocol::ofmatch::Match;
/// use openflow::protocol::{oxm, rule::Rule};
///
/// let mut rule = Rule::add(
///     0,
///     0,   // table
///     100, // priority
///     Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
///     vec![Instruction::apply_actions(vec![Action::output(2)])],
/// );
/// rule.idle_timeout = 30;
/// rule.flags = OFPFF_SEND_FLOW_REM;
/// let rule = rule.with_cookie(0xdead_beef);
/// assert_eq!(rule.cookie, 0xdead_beef);
/// ```
pub struct Rule {
    /// Transaction id. Overwritten by
    /// [`crate::client::Connection::send_flow_mod`], so it can be left 0
    /// when sending through a `Connection`.
    pub xid: u32,
    /// An opaque value the controller chooses to tag this entry
    /// with; it comes back in flow stats and `OFPT_FLOW_REMOVED`.
    pub cookie: u64,
    /// Which `cookie` bits must match for a modify or delete to
    /// apply. Zero matches every entry regardless of cookie.
    pub cookie_mask: u64,
    /// Table to operate on, or `OFPTT_ALL` for a delete across
    /// every table.
    pub table_id: u8,
    /// The `OFPFC_*` command: add, modify, modify-strict, delete,
    /// or delete-strict.
    pub command: u8,
    /// Seconds without a match before the entry expires;
    /// `OFP_FLOW_PERMANENT` (0) never expires.
    pub idle_timeout: u16,
    /// Seconds after installation before the entry expires
    /// regardless of traffic; `OFP_FLOW_PERMANENT` (0) never expires.
    pub hard_timeout: u16,
    /// Match precedence -- the highest-priority matching entry
    /// wins. A wildcard (empty) match should sit at priority 0.
    pub priority: u16,
    /// A buffered packet to release when this entry is added,
    /// or `OFP_NO_BUFFER` for none.
    pub buffer_id: u32,
    /// Restricts a delete or modify to entries with this output
    /// port; `OFPP_ANY` for no restriction. Ignored by add.
    pub out_port: u32,
    /// Restricts a delete or modify to entries with this output
    /// group; `OFPG_ANY` for no restriction. Ignored by add.
    pub out_group: u32,
    /// Bitmask of `OFPFF_*` -- notably `OFPFF_SEND_FLOW_REM`,
    /// which asks for an `OFPT_FLOW_REMOVED` when the entry goes away.
    pub flags: u16,
    /// Eviction importance (1.5 only): when a table is full and
    /// eviction is enabled, lower-importance entries are removed first.
    pub importance: u16,
    /// The fields a packet must carry to match this entry.
    pub of_match: Match,
    /// What to do with matching packets. Empty means drop.
    pub instructions: Vec<Instruction>,
}

impl Rule {
    /// An `OFPFC_ADD` flow-mod: permanent, no cookie, no flags,
    /// `OFPP_ANY`/`OFPG_ANY`, `OFP_NO_BUFFER`.
    ///
    /// `xid` is overwritten when sent through a
    /// [`crate::client::Connection`], so pass 0 unless you are encoding
    /// the frame yourself.
    #[must_use]
    pub const fn add(
        xid: u32,
        table_id: u8,
        priority: u16,
        of_match: Match,
        instructions: Vec<Instruction>,
    ) -> Self {
        Self {
            xid,
            cookie: 0,
            cookie_mask: 0,
            table_id,
            command: OFPFC_ADD,
            idle_timeout: OFP_FLOW_PERMANENT,
            hard_timeout: OFP_FLOW_PERMANENT,
            priority,
            buffer_id: OFP_NO_BUFFER,
            out_port: OFPP_ANY,
            out_group: OFPG_ANY,
            flags: 0,
            importance: 0,
            of_match,
            instructions,
        }
    }

    /// An `OFPFC_DELETE` flow-mod for every entry matching `of_match`.
    ///
    /// `cookie_mask` is `u64::MAX`, so the default cookie of 0 deletes
    /// only entries tagged with cookie 0 -- set both with
    /// [`Self::with_cookie`], or clear the mask with
    /// [`Self::with_cookie_mask`], to delete regardless. An empty
    /// `of_match` deletes the whole table.
    #[must_use]
    pub const fn delete(xid: u32, table_id: u8, of_match: Match) -> Self {
        Self {
            xid,
            cookie: 0,
            cookie_mask: u64::MAX,
            table_id,
            command: OFPFC_DELETE,
            idle_timeout: OFP_FLOW_PERMANENT,
            hard_timeout: OFP_FLOW_PERMANENT,
            priority: 0,
            buffer_id: OFP_NO_BUFFER,
            out_port: OFPP_ANY,
            out_group: OFPG_ANY,
            flags: 0,
            importance: 0,
            of_match,
            instructions: Vec::new(),
        }
    }

    /// Tag this entry with `cookie`.
    #[must_use]
    pub const fn with_cookie(mut self, cookie: u64) -> Self {
        self.cookie = cookie;
        self
    }

    /// Set which cookie bits a modify or delete must match. Zero matches
    /// every entry.
    #[must_use]
    pub const fn with_cookie_mask(mut self, cookie_mask: u64) -> Self {
        self.cookie_mask = cookie_mask;
        self
    }

    /// Restrict a delete or modify to entries outputting to `out_port`.
    #[must_use]
    pub const fn with_out_port(mut self, out_port: u32) -> Self {
        self.out_port = out_port;
        self
    }

    /// Restrict a delete or modify to entries outputting to `out_group`.
    #[must_use]
    pub const fn with_out_group(mut self, out_group: u32) -> Self {
        self.out_group = out_group;
        self
    }

    /// Encode this flow-mod as a complete `OFPT_FLOW_MOD` frame.
    /// # Errors
    ///
    /// Returns an error if the match, instructions, or complete flow-mod
    /// exceeds a wire `u16` length.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();

        body.extend_from_slice(&self.cookie.to_be_bytes());
        body.extend_from_slice(&self.cookie_mask.to_be_bytes());

        body.push(self.table_id);
        body.push(self.command);
        body.extend_from_slice(&self.idle_timeout.to_be_bytes());
        body.extend_from_slice(&self.hard_timeout.to_be_bytes());
        body.extend_from_slice(&self.priority.to_be_bytes());
        body.extend_from_slice(&self.buffer_id.to_be_bytes());
        body.extend_from_slice(&self.out_port.to_be_bytes());
        body.extend_from_slice(&self.out_group.to_be_bytes());
        body.extend_from_slice(&self.flags.to_be_bytes());
        body.extend_from_slice(&self.importance.to_be_bytes());

        self.of_match.encode(&mut body)?;
        for inst in &self.instructions {
            inst.encode(&mut body)?;
        }

        let len = checked_u16_len(OFP_HEADER_LEN + body.len())?;
        let mut out = Vec::with_capacity(usize::from(len));
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_FLOW_MOD,
            length: len,
            xid: self.xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// The standard table-miss entry: an empty match at priority 0 that
    /// sends the whole packet to the controller.
    ///
    /// Without it a switch silently drops unmatched packets, so a
    /// controller that wants packet-ins must install one. See
    /// `examples/03_table_miss.rs`.
    #[must_use]
    pub fn table_miss_to_controller(xid: u32) -> Self {
        use crate::protocol::action::Action;
        Self::add(
            xid,
            0,
            0,
            Match::any(),
            vec![Instruction::apply_actions(vec![
                Action::output_controller_no_buffer(),
            ])],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A flow-table modification received from the wire.
///
/// This is the **decode** side of [`Rule`]: same fields, but the match
/// arrives as raw OXM bytes rather than a typed [`Match`], since a peer
/// may send fields this crate does not model. Produced by
/// [`crate::protocol::codec::Decoder::flow_mod`] and carried by
/// [`crate::protocol::message::Message::FlowMod`].
pub struct Entry {
    /// Transaction id. Overwritten by
    /// [`crate::client::Connection::send_flow_mod`], so it can be left 0
    /// when sending through a `Connection`.
    pub xid: u32,
    /// An opaque value the controller chooses to tag this entry
    /// with; it comes back in flow stats and `OFPT_FLOW_REMOVED`.
    pub cookie: u64,
    /// Which `cookie` bits must match for a modify or delete to
    /// apply. Zero matches every entry regardless of cookie.
    pub cookie_mask: u64,
    /// Table to operate on, or `OFPTT_ALL` for a delete across
    /// every table.
    pub table_id: u8,
    /// The `OFPFC_*` command: add, modify, modify-strict, delete,
    /// or delete-strict.
    pub command: u8,
    /// Seconds without a match before the entry expires;
    /// `OFP_FLOW_PERMANENT` (0) never expires.
    pub idle_timeout: u16,
    /// Seconds after installation before the entry expires
    /// regardless of traffic; `OFP_FLOW_PERMANENT` (0) never expires.
    pub hard_timeout: u16,
    /// Match precedence -- the highest-priority matching entry
    /// wins. A wildcard (empty) match should sit at priority 0.
    pub priority: u16,
    /// A buffered packet to release when this entry is added,
    /// or `OFP_NO_BUFFER` for none.
    pub buffer_id: u32,
    /// Restricts a delete or modify to entries with this output
    /// port; `OFPP_ANY` for no restriction. Ignored by add.
    pub out_port: u32,
    /// Restricts a delete or modify to entries with this output
    /// group; `OFPG_ANY` for no restriction. Ignored by add.
    pub out_group: u32,
    /// Bitmask of `OFPFF_*` -- notably `OFPFF_SEND_FLOW_REM`,
    /// which asks for an `OFPT_FLOW_REMOVED` when the entry goes away.
    pub flags: u16,
    /// Eviction importance (1.5 only): when a table is full and
    /// eviction is enabled, lower-importance entries are removed first.
    pub importance: u16,
    /// The complete `ofp_match`, **including its 4-byte type/length
    /// header** -- unlike the `of_match` fields elsewhere in this crate,
    /// which hold the OXM TLVs alone.
    ///
    /// So decode it by skipping that header:
    ///
    /// ```no_run
    /// # use openflow::protocol::{oxm, rule::Entry};
    /// # fn f(entry: &Entry) -> Result<(), openflow::protocol::error::OfError> {
    /// let fields = oxm::parse_oxm_list(entry.of_match.get(4..).unwrap_or_default())?;
    /// # let _ = fields;
    /// # Ok(())
    /// # }
    /// ```
    pub of_match: Vec<u8>,
    /// What to do with matching packets. Empty means drop.
    pub instructions: Vec<Instruction>,
}

impl Entry {
    /// Convert a decoded wire flow-mod into the controller's rule
    /// representation.
    ///
    /// The decoder retains the complete `ofp_match` header so it can
    /// round-trip the peer's bytes. The rule representation stores the
    /// individual OXM TLVs instead; this method validates the embedded header
    /// and splits the validated list without losing masks or experimenter
    /// fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the embedded match is truncated or has a type
    /// other than `OFPMT_OXM`, or when its OXM list is malformed.
    pub fn into_rule(self) -> Result<Rule> {
        let match_type = read_u16(&self.of_match, 0)?;
        if match_type != OFPMT_OXM {
            return Err(OfError::InvalidValue {
                field: "match_type",
                value: u64::from(match_type),
            });
        }
        let match_length = usize::from(read_u16(&self.of_match, 2)?);
        if match_length < 4 || match_length > self.of_match.len() {
            return Err(OfError::InvalidLength(
                u16::try_from(match_length).unwrap_or(u16::MAX),
            ));
        }
        let fields = oxm::parse_oxm_list(
            self.of_match
                .get(4..match_length)
                .ok_or(OfError::ShortBuffer)?,
        )?;
        let of_match = Match::new(
            fields
                .iter()
                .map(|field| oxm::encode_tlv_list(std::slice::from_ref(field)))
                .collect::<Result<Vec<_>>>()?,
        );
        Ok(Rule {
            xid: self.xid,
            cookie: self.cookie,
            cookie_mask: self.cookie_mask,
            table_id: self.table_id,
            command: self.command,
            idle_timeout: self.idle_timeout,
            hard_timeout: self.hard_timeout,
            priority: self.priority,
            buffer_id: self.buffer_id,
            out_port: self.out_port,
            out_group: self.out_group,
            flags: self.flags,
            importance: self.importance,
            of_match,
            instructions: self.instructions,
        })
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let header = Header::parse(frame)?;
        if header.msg_type != OFPT_FLOW_MOD {
            return Err(OfError::UnknownMessageType(header.msg_type));
        }
        let msg_len = usize::from(header.length);
        if frame.len() < msg_len {
            return Err(OfError::ShortBuffer);
        }
        if msg_len < OFP_HEADER_LEN + 48 {
            return Err(OfError::InvalidLength(header.length));
        }
        let body = frame
            .get(OFP_HEADER_LEN..msg_len)
            .ok_or(OfError::ShortBuffer)?;
        let command = *body.get(17).ok_or(OfError::ShortBuffer)?;
        if !matches!(
            command,
            OFPFC_ADD | OFPFC_MODIFY | OFPFC_MODIFY_STRICT | OFPFC_DELETE | OFPFC_DELETE_STRICT
        ) {
            return Err(OfError::InvalidValue {
                field: "flow_mod_command",
                value: u64::from(command),
            });
        }

        let match_type = read_u16(body, 40)?;
        if match_type != OFPMT_OXM {
            return Err(OfError::InvalidValue {
                field: "match_type",
                value: u64::from(match_type),
            });
        }

        let match_len = usize::from(read_u16(body, 42)?);
        if match_len < 4 {
            return Err(OfError::InvalidLength(
                u16::try_from(match_len).unwrap_or(u16::MAX),
            ));
        }
        let match_padded = match_len.div_ceil(8) * 8;
        if body.len() < 40 + match_padded {
            return Err(OfError::ShortBuffer);
        }
        let _ = body
            .get(40 + match_len..40 + match_padded)
            .ok_or(OfError::ShortBuffer)?;

        oxm::parse_oxm_list(body.get(44..40 + match_len).unwrap_or_default())?;

        Self::parse_body(header.xid, body, command, match_len, match_padded)
    }
}

impl Entry {
    fn parse_body(
        xid: u32,
        body: &[u8],
        command: u8,
        match_len: usize,
        match_padded: usize,
    ) -> Result<Self> {
        Ok(Self {
            xid,
            cookie: read_u64(body, 0)?,
            cookie_mask: read_u64(body, 8)?,
            table_id: *body.get(16).ok_or(OfError::ShortBuffer)?,
            command,
            idle_timeout: read_u16(body, 18)?,
            hard_timeout: read_u16(body, 20)?,
            priority: read_u16(body, 22)?,
            buffer_id: read_u32(body, 24)?,
            out_port: read_u32(body, 28)?,
            out_group: read_u32(body, 32)?,
            flags: read_u16(body, 36)?,
            importance: read_u16(body, 38)?,
            of_match: body
                .get(40..40 + match_len)
                .ok_or(OfError::ShortBuffer)?
                .to_vec(),
            instructions: parse_instructions(
                body.get(40 + match_padded..).ok_or(OfError::ShortBuffer)?,
            )?,
        })
    }
}

/// Encode the standard table-miss flow-mod as a frame.
///
/// Low-level form of
/// [`crate::protocol::codec::Encoder::table_miss_to_controller`].
///
/// # Errors
///
/// Returns an error if the encoded frame exceeds the wire length limit.
pub fn encode_table_miss_to_controller(xid: u32) -> Result<Vec<u8>> {
    Rule::table_miss_to_controller(xid).encode()
}

#[cfg(all(test, not(clippy)))]
mod tests {
    use super::{Entry, Rule};
    use crate::protocol::ofmatch::Match;
    use crate::protocol::oxm;

    #[test]
    fn decoded_entry_converts_to_datapath_rule_without_losing_oxms() {
        let rule = Rule::add(
            9,
            0,
            10,
            Match::new(vec![oxm::eth_type(
                crate::protocol::constants::ETH_TYPE_IPV4,
            )]),
            Vec::new(),
        );
        let entry = Entry::parse(&rule.encode().unwrap()).unwrap();
        let converted = entry.into_rule().unwrap();
        assert_eq!(converted.of_match, rule.of_match);
        assert_eq!(converted.instructions, rule.instructions);
        assert_eq!(converted.xid, rule.xid);
    }
}
