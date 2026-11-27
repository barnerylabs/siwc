//! The query of a request to the callback path, which any local program or
//! web page can send: once as it came, once behind the attempt's own state.
#![no_main]

use libfuzzer_sys::fuzz_target;
use siwc::protocol::Callback;
use siwc_fuzz::attempt;

fuzz_target!(|query: &str| {
    let (attempt, state) = attempt();
    if let Callback::Unrelated(pending) = attempt.accept(query) {
        let owned = format!("state={state}&code=fuzz-code&client_id=app_fuzz0001");
        assert!(matches!(pending.accept(&owned), Callback::Final(Ok(_))));
    }
    let (pending, _) = siwc_fuzz::attempt();
    // The first state is wrong; another state in the input makes it a duplicate.
    assert!(matches!(
        pending.accept(&format!("state=unrelated&{query}")),
        Callback::Unrelated(_)
    ));
    let (attempt, _) = siwc_fuzz::attempt();
    let _owned = attempt.accept(&format!("state={state}&{query}"));
    let (attempt, _) = siwc_fuzz::attempt();
    let _pasted_raw = attempt.accept_redirect(query);
    let (attempt, state) = siwc_fuzz::attempt();
    let _pasted_owned = attempt.accept_redirect(&format!(
        "http://127.0.0.1:8765/auth/callback?state={state}&{query}"
    ));
});
