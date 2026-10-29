// Unverified: written from Railway's Infrastructure as Code docs, never applied.
// Railway builds the Dockerfile without this file; it adds what the image
// can't carry: Postgres, the health check, and one replica for the relay.
import { defineRailway, github, postgres, project, service } from "railway/iac";

export default defineRailway(() => {
  const db = postgres("postgres");

  const server = service("ilo-server", {
    source: github("MartinPTielemans/ilo-server", { branch: "main" }),
    healthcheck: "/health",
    replicas: 1,
    env: { DATABASE_URL: db.env.DATABASE_URL },
  });

  return project("ilo", { resources: [server, db] });
});
