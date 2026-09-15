//! Reference MoQ server: a reflexive origin with no auth, cluster, or cache.
//!
//! Whatever a client publishes lands in one shared origin and is served back to
//! every subscriber of that path, including the publisher's own session. That makes
//! it both a baseline peer for a same-stack measurement and a known-good fixture for
//! validating a client or a hook placement before a real relay is involved.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use moq_bench::object::TRACK;
use moq_bench::stats::Stats;
use moq_bench::{ShapeArgs, install_crypto, publish, versions};
use moq_net::Origin;
use moq_net::broadcast;

#[derive(Parser)]
#[command(version, about = "Reference MoQ server for trace measurements")]
struct Args {
    /// Synthetic broadcasts published into the origin before any client connects.
    #[arg(long, env = "MOQ_BENCH_BROADCASTS", default_value_t = 0)]
    broadcasts: u64,

    /// Namespace prefix for those synthetic broadcasts, published at `<name>/<index>`.
    #[arg(long, env = "MOQ_BENCH_NAME", default_value = "bench")]
    name: String,

    /// How often to log counters for the synthetic broadcasts.
    #[arg(long, value_parser = humantime::parse_duration, env = "MOQ_BENCH_REPORT", default_value = "1s")]
    report: Duration,

    #[command(flatten)]
    shape: ShapeArgs,

    #[command(flatten)]
    log: moq_native::Log,

    #[command(flatten)]
    server: moq_native::ServerConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_crypto();
    let args = Args::parse();
    args.log.init()?;

    let mut config = args.server.clone();
    config.version = versions().iter().copied().collect();
    let mut server = config.init()?;

    // One origin backs the whole server, so a broadcast published by any client is
    // visible to every other client. This is the same shape the relay uses, minus
    // the cluster, auth, and cache layered on top of it.
    let origin = Origin::random().produce();
    let mut published = Vec::new();

    if args.broadcasts > 0 {
        let stats = Arc::new(Stats::default());
        tokio::spawn(stats.clone().report(args.report));

        for index in 0..args.broadcasts {
            let path = format!("{}/{index}", args.name);
            let mut broadcast = origin
                .create_broadcast(path.clone(), broadcast::Route::new().with_announce(true))?;
            let track = broadcast.create_track(TRACK, None)?;
            let task_stats = stats.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    publish::produce(path.clone(), args.shape.into(), track, task_stats).await
                {
                    tracing::warn!(%path, %err, "publisher ended");
                }
            });
            // Hold each broadcast open for the life of the server so it stays announced.
            published.push(broadcast);
        }
    }

    if let Ok(addr) = server.local_addr() {
        tracing::info!(%addr, "listening");
    }

    let serving = async {
        while let Some(request) = server.accept().await {
            let origin = origin.clone();
            tokio::spawn(async move {
                // The roles read from the server's side: we publish into this client
                // whatever the origin holds, and we subscribe to whatever the client
                // publishes so it lands in that same origin.
                match request
                    .with_publisher(&origin)
                    .with_subscriber(origin.clone())
                    .ok()
                    .await
                {
                    Ok(session) => {
                        tracing::info!(version = %session.version(), "session accepted");
                        let _ = session.closed().await;
                    }
                    Err(err) => tracing::warn!(%err, "session rejected"),
                }
            });
        }
    };

    tokio::select! {
        biased;
        () = shutdown() => tracing::info!("interrupted, stopping"),
        () = serving => tracing::warn!("stopped accepting connections"),
    }

    // `published` outlives the accept loop on purpose: dropping a broadcast handle
    // retracts its announcement.
    drop(published);
    Ok(())
}

async fn shutdown() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::warn!(%err, "failed to listen for interrupt");
    }
}
