//! Stream examples should pass deltas to the app as they arrive. Whole
//! answers go through the bounded collector.

#[test]
fn the_public_stream_examples_pass_deltas_on_and_check_the_ending() {
    let sources = [
        ("plan", include_str!("../../src/plan.rs")),
        ("SseDecoder", include_str!("../../src/plan/sse.rs")),
        (
            "ResponseStream",
            include_str!("../../src/client/response.rs"),
        ),
        (
            "AsyncResponseStream",
            include_str!("../../src/client/response_async.rs"),
        ),
    ];
    let mut problems = Vec::new();
    for (name, source) in sources {
        let docs = source
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                line.strip_prefix("///")
                    .or_else(|| line.strip_prefix("//!"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut streams = 0;
        let mut decoder = false;
        for example in docs.split("```").skip(1).step_by(2) {
            if !example.contains("text_delta()") && !example.contains("StreamEvent::TextDelta") {
                continue;
            }
            streams += 1;
            if example.contains(".push_str(")
                || !["show(text)", "show(&delta)"]
                    .iter()
                    .any(|call| example.contains(call))
            {
                problems.push((name, "pass each delta to its consumer"));
            }
            if example.contains("decoder.feed(") {
                decoder = true;
                if example.contains("panic!(") || !example.contains("decoder.finish()?") {
                    problems.push((name, "let finish classify the ending"));
                }
            }
        }
        assert!(streams > 0, "missing stream example for {name}");
        if matches!(name, "plan" | "SseDecoder") && !decoder {
            problems.push((name, "include a decoder example"));
        }
        if name == "plan" && !docs.contains(".into_text()") {
            problems.push((name, "collect a whole answer with into_text"));
        }
    }
    assert!(problems.is_empty(), "{problems:?}");
}
