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
    /// the sender's state is Down or AdminDown. Authenticated packets (the `A` bit
    /// set) are rejected — Wren does not implement BFD authentication. Returns `None`
    /// for a malformed or unsupported packet, which the caller silently discards.
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

        // RFC 5880 §6.8.6 reception rules enforceable on the packet alone.
        if auth_present || multipoint || detect_mult == 0 {
            return None;
        }
        if length < MANDATORY_LEN || length > buf.len() {
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
    fn rejects_authenticated_and_multipoint_packets() {
        let mut b = sample().encode();
        b[1] |= 1 << 2; // A bit — we do not implement auth
        assert!(ControlPacket::decode(&b).is_none());

        let mut b = sample().encode();
        b[1] |= 1; // M bit — must be zero
        assert!(ControlPacket::decode(&b).is_none());
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
}
