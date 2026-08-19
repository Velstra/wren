//! The BFD Control packet wire codec (RFC 5880 §4.1).
//!
//! Only the mandatory section is modelled — 24 octets, no authentication (the
//! `A` bit is always clear). The layout:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Vers|  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       My Discriminator                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Your Discriminator                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Desired Min TX Interval                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Required Min RX Interval                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Required Min Echo RX Interval                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The three interval fields are microseconds.

/// The BFD version this implementation speaks (RFC 5880): version 1.
pub const VERSION: u8 = 1;

/// The length in octets of the mandatory (no-authentication) Control packet.
pub const MANDATORY_LEN: usize = 24;

/// The shortest a packet may state its Length as when the `A` bit is set: the
/// mandatory section plus the two octets an Authentication Section needs before
/// its own length field can be read (RFC 5880 §6.8.6).
pub const MIN_AUTHENTICATED_LEN: usize = 26;

/// The session state carried in the two-bit `Sta` field (RFC 5880 §6.8.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// The session is down (or has just been created).
    Down,
    /// The session is being initialised — we hear the neighbour but it does not
    /// yet hear us.
    Init,
    /// The session is up: both systems hear each other.
    Up,
    /// The session is administratively down.
    AdminDown,
}

impl State {
    /// The two-bit on-the-wire encoding (RFC 5880 §4.1).
    pub fn to_bits(self) -> u8 {
        match self {
            State::AdminDown => 0,
            State::Down => 1,
            State::Init => 2,
            State::Up => 3,
        }
    }

    /// Decode the two-bit `Sta` field.
    pub fn from_bits(bits: u8) -> State {
        match bits & 0b11 {
            0 => State::AdminDown,
            1 => State::Down,
            2 => State::Init,
            _ => State::Up,
        }
    }

    /// A short human label for `show bfd`.
    pub fn label(self) -> &'static str {
        match self {
            State::AdminDown => "AdminDown",
            State::Down => "Down",
            State::Init => "Init",
            State::Up => "Up",
        }
    }
}

/// The diagnostic code a system reports for why its session last changed state
/// (RFC 5880 §4.1). Only the codes Wren originates are named; others round-trip as
/// their raw value via [`Diag::from_code`]/[`Diag::code`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Diag {
    /// 0 — No Diagnostic.
    None,
    /// 1 — Control Detection Time Expired (we stopped hearing the neighbour).
    ControlDetectionTimeExpired,
    /// 2 — Echo Function Failed (looped-back Echo packets stopped returning).
    EchoFunctionFailed,
    /// 3 — Neighbor Signaled Session Down.
    NeighborSignaledDown,
    /// 7 — Administratively Down.
    AdministrativelyDown,
    /// Any other code, kept verbatim.
    Other(u8),
}

impl Diag {
    /// The five-bit diagnostic code.
    pub fn code(self) -> u8 {
        match self {
            Diag::None => 0,
            Diag::ControlDetectionTimeExpired => 1,
            Diag::EchoFunctionFailed => 2,
            Diag::NeighborSignaledDown => 3,
            Diag::AdministrativelyDown => 7,
            Diag::Other(c) => c & 0x1f,
        }
    }

    /// Decode a five-bit diagnostic code.
    pub fn from_code(code: u8) -> Diag {
        match code & 0x1f {
            0 => Diag::None,
            1 => Diag::ControlDetectionTimeExpired,
            2 => Diag::EchoFunctionFailed,
            3 => Diag::NeighborSignaledDown,
            7 => Diag::AdministrativelyDown,
            c => Diag::Other(c),
        }
    }
}

/// A decoded BFD Control packet (mandatory section, RFC 5880 §4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ControlPacket {
    /// The reported diagnostic (why state last changed).
    pub diag: Diag,
    /// The sender's session state.
    pub state: State,
    /// Poll: the sender requests an immediate response (`F`-flagged) packet.
    pub poll: bool,
    /// Final: this packet answers a received Poll.
    pub final_: bool,
    /// Control Plane Independent (`C`). Wren clears it (control-plane dependent).
    pub cpi: bool,
    /// Demand (`D`): the sender wishes to operate in Demand mode. Wren clears it.
    pub demand: bool,
    /// Detect Mult: the neighbour's detection-time multiplier.
    pub detect_mult: u8,
    /// My Discriminator: the sender's unique session id (non-zero).
    pub my_discr: u32,
    /// Your Discriminator: the sender's view of *our* discriminator (0 if unknown).
    pub your_discr: u32,
    /// Desired Min TX Interval (microseconds): how fast the sender wants to transmit.
    pub desired_min_tx: u32,
    /// Required Min RX Interval (microseconds): the slowest the sender can receive.
    pub required_min_rx: u32,
    /// Required Min Echo RX Interval (microseconds); 0 disables Echo (Wren sets 0).
    pub required_min_echo_rx: u32,
    /// Authentication Present (`A`): a decoded packet carried an Authentication
    /// Section. Whether to accept or reject it is the caller's policy (it depends on
    /// whether the session is configured for authentication); the verification of the
    /// section itself is [`crate::auth`]. `encode` always clears it — the runner adds
    /// the auth section (and sets the bit) on the raw bytes.
    pub auth_present: bool,
}

impl ControlPacket {
    /// Serialise into the 24-octet mandatory wire form. The `M` (Multipoint) and
    /// `A` (Authentication Present) bits are always clear; Length is fixed at 24.
    pub fn encode(&self) -> [u8; MANDATORY_LEN] {
        let mut b = [0u8; MANDATORY_LEN];
        // Vers (3 bits) | Diag (5 bits).
        b[0] = (VERSION << 5) | self.diag.code();
        // Sta (2) | P | F | C | A | D | M.
        let mut flags = self.state.to_bits() << 6;
        if self.poll {
            flags |= 1 << 5;
        }
        if self.final_ {
            flags |= 1 << 4;
        }
        if self.cpi {
            flags |= 1 << 3;
        }
        // A (auth) and M (multipoint) stay clear.
        if self.demand {
            flags |= 1 << 1;
        }
        b[1] = flags;
        b[2] = self.detect_mult;
        b[3] = MANDATORY_LEN as u8;
        b[4..8].copy_from_slice(&self.my_discr.to_be_bytes());
        b[8..12].copy_from_slice(&self.your_discr.to_be_bytes());
        b[12..16].copy_from_slice(&self.desired_min_tx.to_be_bytes());
        b[16..20].copy_from_slice(&self.required_min_rx.to_be_bytes());
        b[20..24].copy_from_slice(&self.required_min_echo_rx.to_be_bytes());
        b
    }

    /// Parse a received datagram, applying the RFC 5880 §6.8.6 reception checks that
    /// can be made on the packet alone: version 1, a Length of at least 24 that does
    /// not exceed the datagram, a non-zero Detect Mult, the Multipoint bit clear, a
    /// non-zero My Discriminator, and a Your Discriminator that may only be zero when
    /// the sender's state is Down or AdminDown. The `A` (Authentication Present) bit is
    /// recorded in [`ControlPacket::auth_present`] but not acted on here — accepting or
    /// rejecting an authenticated packet, and verifying its Authentication Section, is
    /// the caller's job ([`crate::auth`]), since it depends on the session's
    /// configuration. Returns `None` for a malformed or unsupported packet, which the
    /// caller silently discards.
    pub fn decode(buf: &[u8]) -> Option<ControlPacket> {
        if buf.len() < MANDATORY_LEN {
            return None;
        }
        let version = buf[0] >> 5;
        if version != VERSION {
            return None;
        }
        let diag = Diag::from_code(buf[0] & 0x1f);
        let state = State::from_bits(buf[1] >> 6);
        let poll = buf[1] & (1 << 5) != 0;
        let final_ = buf[1] & (1 << 4) != 0;
        let cpi = buf[1] & (1 << 3) != 0;
        let auth_present = buf[1] & (1 << 2) != 0;
        let demand = buf[1] & (1 << 1) != 0;
        let multipoint = buf[1] & 1 != 0;
        let detect_mult = buf[2];
        let length = buf[3] as usize;

        // RFC 5880 §6.8.6 reception rules enforceable on the packet alone. The `A`
        // bit is not a rejection cause here — see the doc comment.
        if multipoint || detect_mult == 0 {
            return None;
        }
        // RFC 5880 §6.8.6: "If the Length field is less than the minimum correct
        // value (24 if the A bit is clear, or 26 if the A bit is set), the
        // packet MUST be discarded." The A-bit half was missing, so a packet
        // claiming authentication while stating a 24-octet length — no room for
        // an Authentication Section at all — decoded here and was handed on with
        // `auth_present: true`.
        //
        // `wren-daemon` re-checks this before verifying, so the daemon was never
        // exposed; the gap is in the primitive, which is what the fuzz target
        // drives and what any second caller would rely on.
        let min_len = if auth_present {
            MIN_AUTHENTICATED_LEN
        } else {
            MANDATORY_LEN
        };
        if length < min_len || length > buf.len() {
            return None;
        }
        let my_discr = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if my_discr == 0 {
            return None;
        }
        let your_discr = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        // Your Discriminator may be zero only while the sender is Down/AdminDown.
        if your_discr == 0 && !matches!(state, State::Down | State::AdminDown) {
            return None;
        }
        let desired_min_tx = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let required_min_rx = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let required_min_echo_rx = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        Some(ControlPacket {
            diag,
            state,
            poll,
            final_,
            cpi,
            demand,
            detect_mult,
            my_discr,
            your_discr,
            desired_min_tx,
            required_min_rx,
            required_min_echo_rx,
            auth_present,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ControlPacket {
        ControlPacket {
            diag: Diag::ControlDetectionTimeExpired,
            state: State::Up,
            poll: true,
            final_: false,
            cpi: false,
            demand: false,
            detect_mult: 3,
            my_discr: 0x0a0b0c0d,
            your_discr: 0x11223344,
            desired_min_tx: 300_000,
            required_min_rx: 300_000,
            required_min_echo_rx: 0,
            auth_present: false,
        }
    }

    #[test]
    fn round_trips_through_the_wire() {
        let p = sample();
        let bytes = p.encode();
        assert_eq!(bytes.len(), MANDATORY_LEN);
        assert_eq!(bytes[3], MANDATORY_LEN as u8); // Length field
        assert_eq!(bytes[0] >> 5, VERSION); // Version
        let back = ControlPacket::decode(&bytes).expect("decodes");
        assert_eq!(back, p);
    }

    #[test]
    fn encodes_the_first_two_octets_per_the_bit_layout() {
        // A foreign hand-decode of the header octets — not via our own decode() — so
        // a symmetric encode/decode bug cannot hide a wrong bit layout (the
        // round-trip-vs-ABI lesson). Down state, diag None, no flags.
        let p = ControlPacket {
            state: State::Down,
            diag: Diag::None,
            poll: false,
            ..sample()
        };
        let b = p.encode();
        // Vers=1 (0b001) in the top 3 bits, Diag=0 → 0b001_00000 = 0x20.
        assert_eq!(b[0], 0x20);
        // Sta=Down=0b01 in the top 2 bits, all flags clear → 0b01_000000 = 0x40.
        assert_eq!(b[1], 0x40);
    }

    #[test]
    fn rejects_wrong_version_and_zero_fields() {
        let mut b = sample().encode();
        b[0] = 2 << 5; // version 2, diag 0
        assert!(ControlPacket::decode(&b).is_none());

        let mut b = sample().encode();
        b[2] = 0; // detect mult 0
        assert!(ControlPacket::decode(&b).is_none());

        let mut b = sample().encode();
        b[4..8].copy_from_slice(&0u32.to_be_bytes()); // my discr 0
        assert!(ControlPacket::decode(&b).is_none());
    }

    #[test]
    fn rejects_multipoint_but_records_auth_present() {
        // The Multipoint bit is always illegal.
        let mut b = sample().encode();
        b[1] |= 1; // M bit — must be zero
        assert!(ControlPacket::decode(&b).is_none());

        // The A bit is recorded, not rejected — the auth policy is the caller's.
        //
        // The packet has to be long enough to *have* an Authentication Section
        // for that to be the question. This used to set the A bit on a bare
        // 24-octet packet and assert it decoded, which RFC 5880 §6.8.6 says must
        // be discarded (minimum 26 when A is set); the assertion is about the
        // policy being deferred, so it is made on a packet that could carry one.
        let mut b = sample().encode().to_vec();
        b[1] |= 1 << 2; // A bit
        b[3] = MIN_AUTHENTICATED_LEN as u8;
        b.extend_from_slice(&[0, 0]); // room for an Authentication Section
        let p = ControlPacket::decode(&b).expect("auth-present packets still decode");
        assert!(p.auth_present);
        // A plain (unauthenticated) packet records the bit as clear.
        assert!(!ControlPacket::decode(&sample().encode()).unwrap().auth_present);
    }

    #[test]
    fn the_a_bit_requires_room_for_an_authentication_section_rfc5880() {
        // §6.8.6: "If the Length field is less than the minimum correct value
        // (24 if the A bit is clear, or 26 if the A bit is set), the packet MUST
        // be discarded." Only the 24 half was checked, so a packet claiming
        // authentication while stating a length with no room for an
        // Authentication Section decoded and was handed on with
        // `auth_present: true` — a claim about bytes that are not there.
        for stated in [MANDATORY_LEN, 25] {
            let mut b = sample().encode().to_vec();
            b[1] |= 1 << 2; // A bit
            b[3] = stated as u8;
            b.resize(stated.max(MANDATORY_LEN), 0);
            assert!(
                ControlPacket::decode(&b).is_none(),
                "a length of {stated} with the A bit set was accepted"
            );
        }
        // 26 is the floor, not a rejection.
        let mut b = sample().encode().to_vec();
        b[1] |= 1 << 2;
        b[3] = MIN_AUTHENTICATED_LEN as u8;
        b.extend_from_slice(&[0, 0]);
        assert!(ControlPacket::decode(&b).is_some(), "the shortest legal authenticated packet was refused");
        // And with the A bit clear, 24 is still legal — the floor moved only for
        // the authenticated case.
        assert!(ControlPacket::decode(&sample().encode()).is_some());
    }

    #[test]
    fn rejects_zero_your_discr_when_sender_claims_up() {
        let mut b = sample().encode();
        // State Up (top two bits 0b11) but Your Discriminator 0 is illegal.
        b[1] = State::Up.to_bits() << 6;
        b[8..12].copy_from_slice(&0u32.to_be_bytes());
        assert!(ControlPacket::decode(&b).is_none());
        // The same with state Down is allowed (the initial handshake).
        b[1] = State::Down.to_bits() << 6;
        assert!(ControlPacket::decode(&b).is_some());
    }

    #[test]
    fn too_short_is_none() {
        assert!(ControlPacket::decode(&[0u8; 10]).is_none());
    }

    /// RFC 5880 §4.1 fixes the 24-octet mandatory section: Detect Mult 2,
    /// Length 3, My Discriminator 4..8, Your Discriminator 8..12, Desired Min
    /// TX Interval 12..16, Required Min RX Interval 16..20, Required Min Echo
    /// RX Interval 20..24 — all big-endian.
    ///
    /// `encodes_the_first_two_octets_per_the_bit_layout` above covers bytes 0
    /// and 1 only; everything past them is round-trip-only, and a round trip
    /// cannot see a swap. My/Your Discriminator transposed means the peer's
    /// §6.8.6 demultiplexing never finds the session, so the adjacency never
    /// leaves Down. Desired-Min-TX and Required-Min-RX transposed silently
    /// negotiates the wrong timers: with asymmetric intervals the detect time
    /// is computed from the wrong number and the session either flaps or takes
    /// far longer than configured to notice a failure.
    #[test]
    fn the_mandatory_section_writes_each_field_at_the_offset_the_rfc_names() {
        let p = ControlPacket {
            detect_mult: 5,
            my_discr: 0x0a0b_0c0d,
            your_discr: 0x1122_3344,
            desired_min_tx: 0x0004_93e0,     // 300000
            required_min_rx: 0x000f_4240,    // 1000000
            required_min_echo_rx: 0x0000_03e8, // 1000
            ..sample()
        };
        let b = p.encode();
        assert_eq!(b.len(), 24, "the mandatory section is 24 octets");
        assert_eq!(b[2], 5, "Detect Mult is byte 2");
        assert_eq!(b[3], 24, "Length is byte 3");
        assert_eq!(&b[4..8], &[0x0a, 0x0b, 0x0c, 0x0d], "My Discriminator is 4..8");
        assert_eq!(&b[8..12], &[0x11, 0x22, 0x33, 0x44], "Your Discriminator is 8..12");
        assert_eq!(&b[12..16], &[0x00, 0x04, 0x93, 0xe0], "Desired Min TX is 12..16");
        assert_eq!(&b[16..20], &[0x00, 0x0f, 0x42, 0x40], "Required Min RX is 16..20");
        assert_eq!(&b[20..24], &[0x00, 0x00, 0x03, 0xe8], "Required Min Echo RX is 20..24");
    }

    /// RFC 5880 §4.1 assigns each flag its own bit of byte 1, below the 2-bit
    /// State field: P = 0x20, F = 0x10, C = 0x08, A = 0x04, D = 0x02, M = 0x01.
    ///
    /// P and F are the Poll Sequence (§6.5). Transpose them and a poll is
    /// answered with another poll rather than a final, so the sequence never
    /// terminates and the two ends renegotiate timers forever. The encoder must
    /// also leave A and M clear — it never authenticates or multipoints — and
    /// setting M would make every conformant peer discard the packet (§6.8.6).
    #[test]
    fn each_control_flag_occupies_the_bit_the_rfc_assigns_it() {
        let base = ControlPacket {
            state: State::AdminDown, // Sta = 0b00, so byte 1 is the flags alone
            poll: false,
            final_: false,
            cpi: false,
            demand: false,
            ..sample()
        };
        let only = |f: &dyn Fn(&mut ControlPacket)| {
            let mut p = base;
            f(&mut p);
            p.encode()[1]
        };
        assert_eq!(only(&|p| p.poll = true), 0x20, "P is bit 5 (0x20)");
        assert_eq!(only(&|p| p.final_ = true), 0x10, "F is bit 4 (0x10)");
        assert_eq!(only(&|p| p.cpi = true), 0x08, "C is bit 3 (0x08)");
        assert_eq!(only(&|p| p.demand = true), 0x02, "D is bit 1 (0x02)");
        assert_eq!(base.encode()[1], 0x00, "no flags set leaves byte 1 zero");
        // A (0x04) and M (0x01) are never set by the encoder.
        let all = ControlPacket {
            poll: true,
            final_: true,
            cpi: true,
            demand: true,
            ..base
        };
        assert_eq!(all.encode()[1] & 0x04, 0, "the A bit is never set by encode");
        assert_eq!(all.encode()[1] & 0x01, 0, "the M bit is never set by encode");
        assert_eq!(all.encode()[1], 0x3a, "P|F|C|D with State AdminDown");
    }

    /// RFC 5880 §4.1 numbers the State field: AdminDown 0, Down 1, Init 2, Up 3,
    /// in the top two bits of byte 1.
    ///
    /// This is the value the peer's §6.8.6 state machine switches on. Renumber
    /// Init and Up and the peer reads a neighbour that has just come up as
    /// still initialising — the three-way handshake never completes and BFD
    /// never declares the path alive, so nothing that depends on it (a RIP or
    /// BGP session using BFD for fast failure detection) ever gets its fast
    /// detection.
    #[test]
    fn the_state_field_uses_the_codes_the_rfc_assigns() {
        for (state, bits) in [
            (State::AdminDown, 0b00u8),
            (State::Down, 0b01),
            (State::Init, 0b10),
            (State::Up, 0b11),
        ] {
            assert_eq!(state.to_bits(), bits, "{state:?} is state code {bits}");
            assert_eq!(State::from_bits(bits), state);
            let p = ControlPacket {
                state,
                poll: false,
                final_: false,
                cpi: false,
                demand: false,
                your_discr: 1, // non-zero so Init/Up are legal to encode
                ..sample()
            };
            assert_eq!(p.encode()[1] >> 6, bits, "State is the top 2 bits of byte 1");
        }
    }

    /// RFC 5880 §4.1 numbers the Diagnostic codes 0..=8, in the low five bits of
    /// byte 0. They are what an operator sees as the reason a session went down;
    /// a wrong code turns "the neighbour signalled it is going away" into
    /// "control detection time expired" in every log and `show` output on the
    /// far side.
    #[test]
    fn the_diagnostic_field_uses_the_codes_the_rfc_assigns() {
        for (diag, code) in [
            (Diag::None, 0u8),
            (Diag::ControlDetectionTimeExpired, 1),
            (Diag::EchoFunctionFailed, 2),
            (Diag::NeighborSignaledDown, 3),
            // 4 (Forwarding Plane Reset), 5 (Path Down), 6 (Concatenated Path
            // Down) and 8 (Reverse Concatenated Path Down) have no named
            // variant; they travel as `Other` and must keep their raw code.
            (Diag::Other(4), 4),
            (Diag::Other(5), 5),
            (Diag::Other(6), 6),
            (Diag::AdministrativelyDown, 7),
            (Diag::Other(8), 8),
        ] {
            assert_eq!(diag.code(), code, "{diag:?} is diagnostic code {code}");
            assert_eq!(Diag::from_code(code), diag);
            let p = ControlPacket { diag, ..sample() };
            let b0 = p.encode()[0];
            assert_eq!(b0 & 0x1f, code, "Diag is the low 5 bits of byte 0");
            assert_eq!(b0 >> 5, 1, "Version 1 stays in the top 3 bits");
        }
    }
}
