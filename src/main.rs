use anyhow::Context;
use ilo_server::config::Config;
use ilo_server::mail::Mailer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    // `ilo-server counts` prints the daily usage count's numbers from DATABASE_URL, and serves
    // nothing.
    if std::env::args().nth(1).as_deref() == Some("counts") {
        return print_counts().await;
    }
    let config = Config::from_env()?;
    let mailer = Mailer::from_config(&config)?;
    if config.dev_mode {
        tracing::warn!("DEV_MODE: sign-in codes go to this log, not by mail");
    }
    let address = (config.host.clone(), config.port);
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .with_context(|| format!("can't listen on {}:{}", address.0, address.1))?;
    let state = ilo_server::state(config, mailer).await?;
    tracing::info!(address = %listener.local_addr()?, issuer = state.config.issuer(), "ilo-server is up");
    axum::serve(
        listener,
        ilo_server::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let interrupt = tokio::signal::ctrl_c();
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("can't watch for SIGTERM");
        #[cfg(unix)]
        tokio::select! { _ = interrupt => {}, _ = terminate.recv() => {} }
        #[cfg(not(unix))]
        let _ = interrupt.await;
    })
    .await?;
    Ok(())
}

/// Daily, weekly and monthly users and new installs, from the database the server uses. It reads
/// the counts table only, so it never migrates the database ahead of the server.
async fn print_counts() -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    let url = std::env::var("DATABASE_URL").context("DATABASE_URL names no database")?;
    let db = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .context("can't open the database")?;
    let today = ilo_server::counts::today();
    let tallies = ilo_server::counts::tallies(&db, today - ilo_server::counts::REPORT_DAYS).await?;
    print!("{}", ilo_server::counts::report(&tallies, today));
    Ok(())
}
