//! Reference MoQ client: a deterministic synthetic workload driver.
//!
//! Publish and subscribe share one session, so a single client pointed at the
//! reference server or at a relay under test exercises both directions of the same
//! object path. Every knob is a scalar rather than a range: the client is the
//! constant side of a cross-implementation measurement, so its offered load has to
//! be the same in every run.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use moq_bench::object::TRACK;
use moq_bench::stats::Stats;
use moq_bench::{ShapeArgs, install_crypto, publish, subscribe, versions};
use moq_net::Origin;
use moq_net::announce;
use moq_net::broadcast;
use tokio::task::JoinSet;

#[derive(Parser)]
#[command(version, about = "Reference MoQ client for trace measurements")]
struct Args {
    /// Broadcast namespace prefix. Broadcasts publish under `<name>/<run>/<index>`.
    #[arg(long, env = "MOQ_BENCH_NAME", default_value = "bench")]
    name: String,

    /// Run identifier embedded in every broadcast path. Random by default.
    #[arg(long, env = "MOQ_BENCH_RUN")]
    run: Option<String>,

    /// Broadcasts published by this session, each with a single track.
    #[arg(long, env = "MOQ_BENCH_BROADCASTS", default_value_t = 1)]
    broadcasts: u64,

    /// Broadcasts this session subscribes to under `<name>`, found via announcements.
    ///
    /// Own broadcasts are included, which is what makes a single-client loopback
    /// measurement through the reference server meaningful.
    #[arg(long, env = "MOQ_BENCH_SUBSCRIBE", default_value_t = 1)]
    subscribe: u64,

    /// Stop after this long. Runs until interrupted if unset.
    #[arg(long, value_parser = humantime::parse_duration, env = "MOQ_BENCH_DURATION")]
    duration: Option<Duration>,

    /// How often to log counters.
    #[arg(long, value_parser = humantime::parse_duration, env = "MOQ_BENCH_REPORT", default_value = "1s")]
    report: Duration,

    #[command(flatten)]
    shape: ShapeArgs,

    #[command(flatten)]
    log: moq_native::Log,

    #[command(flatten)]
    client: moq_native::ClientConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_crypto();
    let args = Args::parse();
    args.log.init()?;

    let url = args
        .client
        .connect
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--client-connect is required"))?;

    let mut config = args.client.clone();
    config.version = versions().iter().copied().collect();

    let stats = Arc::new(Stats::default());
    tokio::spawn(stats.clone().report(args.report));

    // Two origins: one holds what this session publishes, the other is filled with
    // what the peer announces and is where subscriptions are drawn from.
    let published = Origin::random().produce();
    let remote = Origin::random().produce();
    let announced = remote.consume().announced();

    let run = args
        .run
        .clone()
        .unwrap_or_else(|| format!("{:x}", std::process::id()));
    let mut broadcasts = Vec::new();
    for index in 0..args.broadcasts {
        let path = format!("{}/{run}/{index}", args.name);
        let mut broadcast = published
            .create_broadcast(path.clone(), broadcast::Route::new().with_announce(true))?;
        let track = broadcast.create_track(TRACK, None)?;
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(err) = publish::produce(path.clone(), args.shape.into(), track, stats).await
            {
                tracing::warn!(%path, %err, "publisher ended");
            }
        });
        // Hold each broadcast open for the run so it stays announced.
        broadcasts.push(broadcast);
    }

    if args.subscribe > 0 {
        tokio::spawn(watch(announced, args.subscribe, stats.clone()));
    }

    let client = config
        .init()?
        .with_publisher(&published)
        .with_subscriber(remote);
    let session = client.connect(url.clone()).await?;
    tracing::info!(version = %session.version(), url = %url, "connected");

    tokio::select! {
        biased;
        () = stop(args.duration) => tracing::info!("duration elapsed, stopping"),
        () = shutdown() => tracing::info!("interrupted, stopping"),
        err = session.closed() => tracing::warn!(%err, "session closed"),
    }

    drop(broadcasts);
    Ok(())
}

/// Subscribe to the first `want` announced broadcasts, including this session's own.
async fn watch(mut announced: announce::Consumer, want: u64, stats: Arc<Stats>) {
    let mut seen = HashSet::new();
    let mut tasks = JoinSet::new();

    while (seen.len() as u64) < want {
        let Some(update) = announced.next().await else {
            break;
        };
        let Some(broadcast) = update.broadcast else {
            continue;
        };

        let path = update.path.as_str().to_string();
        if !seen.insert(path.clone()) {
            continue;
        }

        let stats = stats.clone();
        tasks.spawn(async move {
            if let Err(err) = subscribe::drain(broadcast, stats).await {
                tracing::debug!(%path, %err, "subscription ended");
            }
        });
    }

    while tasks.join_next().await.is_some() {}
}

async fn stop(duration: Option<Duration>) {
    match duration {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}

async fn shutdown() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::warn!(%err, "failed to listen for interrupt");
    }
}
