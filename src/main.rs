use anyhow::Context;
use ilo_server::config::Config;
use ilo_server::mail::Mailer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
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
    axum::serve(listener, ilo_server::router(state))
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
