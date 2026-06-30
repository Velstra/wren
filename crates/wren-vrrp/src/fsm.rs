//! The VRRP virtual-router state machine (RFC 5798 §6.4).
//!
//! Pure and timekeeping-free, in the style of [`wren-bfd`](../../wren_bfd): the
//! machine consumes events (startup, shutdown, a received advertisement, a timer
//! firing) and returns the [`Action`]s the async runner must carry out — sending
//! advertisements, assuming or releasing the virtual IP, and (re)arming the two
//! timers. The runner owns the sockets, the `Instant`s and the kernel.
//!
//! All intervals are in **centiseconds** (1/100 s), the unit VRRP puts on the
//! wire, so the runner converts once at the I/O boundary.

use std::net::IpAddr;

/// The three VRRP states (RFC 5798 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for a Startup event; owns nothing.
    Initialize,
    /// Monitoring the master via its advertisements; ready to take over.
    Backup,
    /// Owns the virtual IP and advertises it.
    Master,
}

impl State {
    /// The lowercase name used in `show vrrp` and logs.
    pub fn name(self) -> &'static str {
        match self {
            State::Initialize => "initialize",
            State::Backup => "backup",
            State::Master => "master",
        }
    }
}

/// One thing the runner must do as a result of an FSM transition. Several are
/// returned in order per event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send an advertisement with our configured priority.
    SendAdvert,
    /// Send an advertisement with priority 0 — a master releasing the address.
    SendAdvertZero,
    /// Assume the virtual IP(s): add them to the interface and announce them with
    /// a gratuitous ARP (IPv4) / unsolicited neighbor advertisement (IPv6).
    AssumeVip,
    /// Release the virtual IP(s): remove them from the interface.
    ReleaseVip,
    /// (Re)arm the advertisement timer to this many centiseconds.
    ArmAdverTimer(u16),
    /// (Re)arm the master-down timer to this many centiseconds.
    ArmMasterDownTimer(u16),
    /// Cancel the advertisement timer.
    CancelAdverTimer,
    /// Cancel the master-down timer.
    CancelMasterDownTimer,
}

/// The static configuration of one virtual router.
#[derive(Debug, Clone)]
pub struct VrrpConfig {
    /// Virtual Router ID (1–255).
    pub vrid: u8,
    /// Our priority (1–255). 255 means we own the address(es) — we start Master and
    /// never yield while up.
    pub priority: u8,
    /// Our configured advertisement interval, in centiseconds.
    pub advert_int_cs: u16,
    /// Whether to preempt a lower-priority master (take over when we have the higher
    /// priority). The address owner (priority 255) always effectively preempts.
    pub preempt: bool,
    /// Our primary IP address on the interface — the election tie-breaker when two
    /// routers advertise the same priority (higher address wins).
    pub local_primary: IpAddr,
    /// The virtual IP address(es) this router backs.
    pub addresses: Vec<IpAddr>,
}

/// The running virtual-router state machine.
#[derive(Debug, Clone)]
pub struct Vrrp {
    cfg: VrrpConfig,
    state: State,
    /// The active master's advertisement interval (centiseconds), learned from its
    /// advertisements; seeded with our own configured interval. Skew and master-down
    /// are derived from this, per RFC 5798 §6.1.
    master_adver_int_cs: u16,
    /// The current master's primary address, for `show vrrp` (ourselves when Master).
    master_addr: Option<IpAddr>,
}

impl Vrrp {
    /// Create a virtual router in the Initialize state.
    pub fn new(cfg: VrrpConfig) -> Self {
        let master_adver_int_cs = cfg.advert_int_cs;
        Vrrp {
            cfg,
            state: State::Initialize,
            master_adver_int_cs,
            master_addr: None,
        }
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Our configured priority.
    pub fn priority(&self) -> u8 {
        self.cfg.priority
    }

    /// The Virtual Router ID.
    pub fn vrid(&self) -> u8 {
        self.cfg.vrid
    }

    /// The virtual IP addresses.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.cfg.addresses
    }

    /// The current master's primary address (ourselves when Master), if known.
    pub fn master_addr(&self) -> Option<IpAddr> {
        self.master_addr
    }

    /// Our configured advertisement interval, in centiseconds.
    pub fn advert_int_cs(&self) -> u16 {
        self.cfg.advert_int_cs
    }

    /// Skew time (centiseconds): `((256 - priority) * Master_Adver_Interval) / 256`
    /// (RFC 5798 §6.1) — a higher-priority backup waits less before taking over.
    pub fn skew_time_cs(&self) -> u16 {
        ((256 - self.cfg.priority as u32) * self.master_adver_int_cs as u32 / 256) as u16
    }

    /// Master-down interval (centiseconds): `3 * Master_Adver_Interval + Skew_Time`.
    pub fn master_down_int_cs(&self) -> u16 {
        3 * self.master_adver_int_cs + self.skew_time_cs()
    }

    /// Startup: enter Master immediately if we own the address (priority 255),
    /// otherwise enter Backup and start the master-down timer.
    pub fn on_startup(&mut self) -> Vec<Action> {
        if self.cfg.priority == 255 {
            self.become_master()
        } else {
            self.state = State::Backup;
            self.master_addr = None;
            vec![Action::ArmMasterDownTimer(self.master_down_int_cs())]
        }
    }

    /// Shutdown: relinquish the address and return to Initialize.
    pub fn on_shutdown(&mut self) -> Vec<Action> {
        let actions = match self.state {
            State::Master => vec![
                Action::CancelAdverTimer,
                Action::SendAdvertZero,
                Action::ReleaseVip,
            ],
            State::Backup => vec![Action::CancelMasterDownTimer],
            State::Initialize => vec![],
        };
        self.state = State::Initialize;
        self.master_addr = None;
        actions
    }

    /// The master-down timer fired (Backup only): no advertisement arrived in time,
    /// so take over as Master.
    pub fn on_master_down_timer(&mut self) -> Vec<Action> {
        if self.state != State::Backup {
            return vec![];
        }
        self.become_master()
    }

    /// The advertisement timer fired (Master only): send the next advertisement and
    /// re-arm.
    pub fn on_adver_timer(&mut self) -> Vec<Action> {
        if self.state != State::Master {
            return vec![];
        }
        vec![Action::SendAdvert, Action::ArmAdverTimer(self.cfg.advert_int_cs)]
    }

    /// An advertisement for our VRID arrived, with the sender's `priority`,
    /// advertised interval `adver_int_cs`, and primary source address `src`.
    pub fn on_advertisement(&mut self, priority: u8, adver_int_cs: u16, src: IpAddr) -> Vec<Action> {
        match self.state {
            State::Initialize => vec![],
            State::Backup => self.advert_in_backup(priority, adver_int_cs, src),
            State::Master => self.advert_in_master(priority, src),
        }
    }

    /// Common Master-entry actions: send an advertisement, assume the address, arm
    /// the advertisement timer.
    fn become_master(&mut self) -> Vec<Action> {
        self.state = State::Master;
        self.master_addr = Some(self.cfg.local_primary);
        vec![
            Action::SendAdvert,
            Action::AssumeVip,
            Action::ArmAdverTimer(self.cfg.advert_int_cs),
        ]
    }

    fn advert_in_backup(&mut self, priority: u8, adver_int_cs: u16, src: IpAddr) -> Vec<Action> {
        if priority == 0 {
            // The master is releasing the address: take over after just the skew time.
            return vec![Action::ArmMasterDownTimer(self.skew_time_cs())];
        }
        // Stay backup and reset the master-down timer when we should not preempt:
        // either preemption is disabled, or the master's priority is at least ours.
        if !self.cfg.preempt || priority >= self.cfg.priority {
            self.master_adver_int_cs = adver_int_cs.max(1);
            self.master_addr = Some(src);
            return vec![Action::ArmMasterDownTimer(self.master_down_int_cs())];
        }
        // preempt && the master is lower priority: ignore it and let our master-down
        // timer expire so we take over.
        vec![]
    }

    fn advert_in_master(&mut self, priority: u8, src: IpAddr) -> Vec<Action> {
        if priority == 0 {
            // A peer is releasing: reassert ourselves immediately.
            return vec![Action::SendAdvert, Action::ArmAdverTimer(self.cfg.advert_int_cs)];
        }
        // Yield to a higher-priority peer, or an equal-priority peer with a higher
        // primary address (RFC 5798 §6.4.3 tie-break).
        let yields = priority > self.cfg.priority
            || (priority == self.cfg.priority && addr_gt(src, self.cfg.local_primary));
        if yields {
            self.state = State::Backup;
            self.master_addr = Some(src);
            vec![
                Action::CancelAdverTimer,
                Action::ReleaseVip,
                Action::ArmMasterDownTimer(self.master_down_int_cs()),
            ]
        } else {
            // We win: ignore the inferior advertisement.
            vec![]
        }
    }
}

/// Whether `a` sorts after `b` for the master-election tie-break (numeric address
/// order; a v4/v6 mismatch can't arise on one virtual router, and falls back to
/// false).
fn addr_gt(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x > y,
        (IpAddr::V6(x), IpAddr::V6(y)) => x > y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(priority: u8, preempt: bool, primary: &str) -> VrrpConfig {
        VrrpConfig {
            vrid: 51,
            priority,
            advert_int_cs: 100, // 1 second
            preempt,
            local_primary: primary.parse().unwrap(),
            addresses: vec!["10.0.0.254".parse().unwrap()],
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn owner_starts_as_master_and_assumes_the_address() {
        let mut v = Vrrp::new(cfg(255, true, "10.0.0.1"));
        let actions = v.on_startup();
        assert_eq!(v.state(), State::Master);
        assert_eq!(
            actions,
            vec![
                Action::SendAdvert,
                Action::AssumeVip,
                Action::ArmAdverTimer(100)
            ]
        );
    }

    #[test]
    fn backup_starts_and_promotes_on_master_down() {
        let mut v = Vrrp::new(cfg(100, true, "10.0.0.2"));
        let actions = v.on_startup();
        assert_eq!(v.state(), State::Backup);
        // master_down = 3*100 + skew; skew = (256-100)*100/256 = 60 → 360 cs.
        assert_eq!(actions, vec![Action::ArmMasterDownTimer(360)]);
        // No advert arrives → the timer fires → we become master.
        let promote = v.on_master_down_timer();
        assert_eq!(v.state(), State::Master);
        assert_eq!(promote[0], Action::SendAdvert);
        assert_eq!(promote[1], Action::AssumeVip);
    }

    #[test]
    fn backup_resets_timer_on_higher_or_equal_advert() {
        let mut v = Vrrp::new(cfg(100, true, "10.0.0.2"));
        v.on_startup();
        // A higher-priority master: stay backup, reset the master-down timer.
        let a = v.on_advertisement(200, 100, ip("10.0.0.1"));
        assert_eq!(v.state(), State::Backup);
        assert_eq!(a, vec![Action::ArmMasterDownTimer(360)]);
        assert_eq!(v.master_addr(), Some(ip("10.0.0.1")));
    }

    #[test]
    fn backup_with_preempt_ignores_a_lower_priority_master() {
        let mut v = Vrrp::new(cfg(200, true, "10.0.0.1"));
        v.on_startup();
        // A lower-priority master while we preempt: ignore it (let our timer fire).
        let a = v.on_advertisement(100, 100, ip("10.0.0.2"));
        assert_eq!(v.state(), State::Backup);
        assert!(a.is_empty());
    }

    #[test]
    fn backup_without_preempt_keeps_a_lower_priority_master() {
        let mut v = Vrrp::new(cfg(200, false, "10.0.0.1"));
        v.on_startup();
        // preempt disabled: respect the sitting master even though it is lower.
        let a = v.on_advertisement(100, 100, ip("10.0.0.2"));
        assert_eq!(v.state(), State::Backup);
        assert_eq!(a, vec![Action::ArmMasterDownTimer(v.master_down_int_cs())]);
    }

    #[test]
    fn master_yields_to_a_higher_priority_advert() {
        let mut v = Vrrp::new(cfg(100, true, "10.0.0.2"));
        v.on_startup();
        v.on_master_down_timer(); // become master
        assert_eq!(v.state(), State::Master);
        let a = v.on_advertisement(200, 100, ip("10.0.0.1"));
        assert_eq!(v.state(), State::Backup);
        assert_eq!(a[0], Action::CancelAdverTimer);
        assert_eq!(a[1], Action::ReleaseVip);
    }

    #[test]
    fn master_holds_against_a_lower_priority_advert() {
        let mut v = Vrrp::new(cfg(200, true, "10.0.0.1"));
        v.on_startup(); // owner? no, priority 200 → backup first
        v.on_master_down_timer();
        assert_eq!(v.state(), State::Master);
        let a = v.on_advertisement(100, 100, ip("10.0.0.2"));
        assert_eq!(v.state(), State::Master);
        assert!(a.is_empty());
    }

    #[test]
    fn master_yields_to_equal_priority_with_higher_address() {
        let mut v = Vrrp::new(cfg(100, true, "10.0.0.2"));
        v.on_startup();
        v.on_master_down_timer();
        // Equal priority but the sender's address is higher → we yield.
        let a = v.on_advertisement(100, 100, ip("10.0.0.9"));
        assert_eq!(v.state(), State::Backup);
        assert_eq!(a[1], Action::ReleaseVip);
    }

    #[test]
    fn shutdown_from_master_releases_with_priority_zero() {
        let mut v = Vrrp::new(cfg(255, true, "10.0.0.1"));
        v.on_startup();
        let a = v.on_shutdown();
        assert_eq!(v.state(), State::Initialize);
        assert_eq!(
            a,
            vec![
                Action::CancelAdverTimer,
                Action::SendAdvertZero,
                Action::ReleaseVip
            ]
        );
    }

    #[test]
    fn priority_zero_advert_in_backup_shortens_to_skew() {
        let mut v = Vrrp::new(cfg(100, true, "10.0.0.2"));
        v.on_startup();
        let a = v.on_advertisement(0, 100, ip("10.0.0.1"));
        assert_eq!(v.state(), State::Backup);
        assert_eq!(a, vec![Action::ArmMasterDownTimer(v.skew_time_cs())]);
    }
}
