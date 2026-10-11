//! Tracing span emission.
//!
//! Own integration binary so sibling tests cannot register the prepare/apply/finish
//! callsites against the no-op dispatcher before this subscriber is installed.

#![cfg(feature = "tracing")]

use std::sync::{Arc, Mutex};

use kekkai::{Sandbox, Settings};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

struct Names {
    names: Arc<Mutex<Vec<&'static str>>>,
    next: Mutex<u64>,
}

impl Subscriber for Names {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, span: &Attributes<'_>) -> Id {
        self.names.lock().unwrap().push(span.metadata().name());
        let mut next = self.next.lock().unwrap();
        *next += 1;
        Id::from_u64(*next)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[test]
fn prepare_apply_finish_emit_tracing_spans() {
    let names = Arc::new(Mutex::new(Vec::new()));
    let subscriber = Names {
        names: Arc::clone(&names),
        next: Mutex::new(0),
    };
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        let sandbox = Sandbox::prepare(&Settings::default(), ".").expect("prepare");
        let mut command = std::process::Command::new("true");
        sandbox.apply(&mut command).expect("apply");
        let _ = sandbox.finish();
    });
    let got = names.lock().unwrap().clone();
    for name in ["kekkai.prepare", "kekkai.apply", "kekkai.finish"] {
        assert!(got.contains(&name), "missing span {name} in {got:?}");
    }
}
