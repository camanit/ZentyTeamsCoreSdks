use zentyteams_sdk::LogicFuzzer;

#[tokio::main]
async fn main() {
    println!(r#"
╔══════════════════════════════════════════════════════════════════════╗
║              ⚔️ ZENTYTEAMSCORE — RED TEAM LOGIC FUZZER ⚔️             ║
║            Automated Business Logic & Race-Condition Burst           ║
╚══════════════════════════════════════════════════════════════════════╝
    "#);

    let fuzzer = LogicFuzzer::new();
    let target = "http://127.0.0.1:8080";

    println!(">>> [CAMPAIGN 1] Menjalankan Fuzzing Mutasi Logika Transaksi QRIS/WebPay...");
    let results = fuzzer.run_payment_fuzz_campaign(target).await;

    for r in &results {
        let status_emoji = if r.was_blocked { "🛡️ BLOCKED (SAFE)" } else { "⚠️ APPROVED (CHECK)" };
        println!(
            "  [{}] Test: {:<30} | Amount: {:>15.2} | Latency: {:>3}ms | Response: {}",
            status_emoji, r.test_name, r.payload_amount, r.latency_ms, r.server_response
        );
    }

    println!("\n>>> [CAMPAIGN 2] Menjalankan Concurrency Burst Test (25 Parallel Tokio Tasks)...");
    let burst = fuzzer.run_concurrency_burst(target, 25).await;

    println!("  Target Endpoint       : {}", burst.target_url);
    println!("  Total Simultaneous Req: {}", burst.total_requests);
    println!("  Approvals (Expected 1): {}", burst.successful_approvals);
    println!("  Blocked Double-Spends : {}", burst.blocked_double_spends);
    println!("  Average Latency       : {:.2} ms", burst.average_latency_ms);
    println!(
        "  Atomic Lock Verdict   : {}",
        if burst.is_atomic_lock_effective {
            "✅ ROBUST & PROTECTED (Celah Double-Spending Tertutup 100%)"
        } else {
            "❌ VULNERABLE TO RACE CONDITION"
        }
    );
}
