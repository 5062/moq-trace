//! Reference MoQ client: a deterministic synthetic workload driver.
//!
//! Publish and subscribe share each session, so a client pointed at the reference
//! server or at a relay under test exercises both directions of the same object
//! path. Every knob is a scalar rather than a range: the client is the constant side
//! of a cross-implementation measurement, so its offered load has to be the same in
//! every run. `--connections` opens several such sessions from one process, which is
//! how a run gets several independent subscribers without several peers. Each session
//! binds its own QUIC endpoint, so it has its own UDP port and endpoint driver just as
//! a separate peer would.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use moq_bench::object::TRACK;
use moq_bench::stats::Stats;
use moq_bench::{Shape, install_crypto, publish, subscribe, versions};
use moq_net::Origin;
use moq_net::announce;
use moq_net::broadcast;
use tokio::task::JoinSet;

#[derive(Parser)]
#[command(version, about = "Reference MoQ client for trace measurements")]
struct Args {
    /// Broadcast namespace prefix. Broadcasts publish under `<name>/<run>/<connection>/<index>`.
    #[arg(long, env = "MOQ_BENCH_NAME", default_value = "bench")]
    name: String,

    /// Run identifier embedded in every broadcast path. Defaults to the process ID.
    #[arg(long, env = "MOQ_BENCH_RUN")]
    run: Option<String>,

    /// Sessions opened by this client. Each one publishes and subscribes on its own.
    #[arg(
        long,
        env = "MOQ_BENCH_CONNECTIONS",
        default_value_t = 1,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    connections: u64,

    /// Broadcasts published per session, each with a single track.
    #[arg(long, env = "MOQ_BENCH_BROADCASTS", default_value_t = 1)]
    broadcasts: u64,

    /// Broadcasts each session subscribes to under `<name>`, found via announcements.
    ///
    /// Own broadcasts are included, which is what makes a loopback measurement
    /// through the reference server meaningful.
    #[arg(long, env = "MOQ_BENCH_SUBSCRIBE", default_value_t = 1)]
    subscribe: u64,

    /// Spread session startup evenly over this duration instead of connecting at once.
    ///
    /// The last session starts one step short of the window and a single session never
    /// waits, which is the connection ramp `rs/moq-bench` applies.
    #[arg(long, value_parser = humantime::parse_duration, env = "MOQ_BENCH_STARTUP", default_value = "0s")]
    startup: Duration,

    /// Stop after this long. Runs until interrupted if unset.
    #[arg(long, value_parser = humantime::parse_duration, env = "MOQ_BENCH_DURATION")]
    duration: Option<Duration>,

    /// How often to log counters.
    #[arg(long, value_parser = humantime::parse_duration, env = "MOQ_BENCH_REPORT", default_value = "1s")]
    report: Duration,

    #[command(flatten)]
    shape: Shape,

    #[command(flatten)]
    log: moq_native::Log,

    #[command(flatten)]
    client: moq_native::ClientConfig,
}

/// Everything one session needs: its identity, its workload, and the shared handles.
struct Session {
    /// Position in the startup ramp, and the connection index of every broadcast path.
    index: u64,
    name: String,
    run: String,
    broadcasts: u64,
    subscribe: u64,
    shape: Shape,
    /// Initialized per session, so sessions never share a socket or endpoint driver.
    config: moq_native::ClientConfig,
    url: url::Url,
    stats: Arc<Stats>,
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

    // A shared endpoint would funnel every session through one socket and one driver
    // task, which a relay sees as a single 4-tuple and which caps fan-out on the
    // client side. Every session therefore binds its own, and a fixed port could only
    // be bound once.
    anyhow::ensure!(
        args.connections == 1 || args.client.bind.port() == 0,
        "--client-bind needs port 0 when --connections is above 1"
    );
    let mut config = args.client.clone();
    config.version = versions().iter().copied().collect();

    let stats = Arc::new(Stats::default());
    tokio::spawn(stats.clone().report(args.report));

    let run = args
        .run
        .clone()
        .unwrap_or_else(|| format!("{:x}", std::process::id()));

    let mut sessions = JoinSet::new();
    for index in 0..args.connections {
        let session = Session {
            index,
            name: args.name.clone(),
            run: run.clone(),
            broadcasts: args.broadcasts,
            subscribe: args.subscribe,
            shape: args.shape,
            config: config.clone(),
            url: url.clone(),
            stats: stats.clone(),
        };
        let delay = startup_delay(args.startup, index, args.connections);
        sessions.spawn(async move {
            tokio::time::sleep(delay).await;
            if let Err(err) = drive(session).await {
                // A client that cannot run its workload has to fail the run loudly.
                // Staying up would leave the runner waiting out its readiness
                // timeouts instead of reading this error.
                tracing::error!(connection = index, %err, "session failed");
                std::process::exit(1);
            }
        });
    }

    tokio::select! {
        biased;
        () = stop(args.duration) => tracing::info!("duration elapsed, stopping"),
        () = shutdown() => tracing::info!("interrupted, stopping"),
        () = async { while sessions.join_next().await.is_some() {} } => {
            tracing::warn!("all sessions ended");
        }
    }

    Ok(())
}

/// Delay before session `index` starts, spreading `startup` evenly across the ramp.
fn startup_delay(startup: Duration, index: u64, connections: u64) -> Duration {
    startup.mul_f64(index as f64 / connections as f64)
}

/// Publish, subscribe, and hold one session open until its peer closes it.
async fn drive(session: Session) -> anyhow::Result<()> {
    let Session {
        index,
        name,
        run,
        broadcasts,
        subscribe,
        shape,
        config,
        url,
        stats,
    } = session;

    let client = config.init()?;

    // Two origins: one holds what this session publishes, the other is filled with
    // what the peer announces and is where subscriptions are drawn from.
    let published = Origin::random().produce();
    let remote = Origin::random().produce();
    let announced = remote.consume().announced();

    // Hold every broadcast producer for the session's lifetime so it stays announced.
    let mut held = Vec::new();
    for broadcast_index in 0..broadcasts {
        let path = format!("{name}/{run}/{index}/{broadcast_index}");
        let mut broadcast = published
            .create_broadcast(path.clone(), broadcast::Route::new().with_announce(true))?;
        let track = broadcast.create_track(TRACK, None)?;
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(err) = publish::produce(shape, track, stats).await {
                tracing::warn!(%path, %err, "publisher ended");
            }
        });
        held.push(broadcast);
    }

    if subscribe > 0 {
        tokio::spawn(watch(announced, subscribe, stats.clone()));
    }

    let client = client.with_publisher(&published).with_subscriber(remote);

    let live = client.connect(url.clone()).await?;
    tracing::info!(version = %live.version(), url = %url, connection = index, "connected");
    // The gauge covers the connected session, not the attempt, so a runner gating on
    // `connections` cannot start a window against a peer that never connected.
    let _gauge = stats.connection();

    let err = live.closed().await;
    tracing::warn!(connection = index, %err, "session closed");

    drop(held);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The ramp spreads sessions evenly and never delays a lone session, which is
    /// what keeps the default single-connection run identical to no ramp at all.
    #[test]
    fn startup_delay_spreads_sessions_evenly() {
        let startup = Duration::from_secs(10);
        assert_eq!(startup_delay(startup, 0, 1), Duration::ZERO);
        assert_eq!(startup_delay(startup, 0, 4), Duration::ZERO);
        assert_eq!(startup_delay(startup, 2, 4), Duration::from_secs(5));
        assert_eq!(startup_delay(startup, 3, 4), Duration::from_millis(7_500));
    }
}
