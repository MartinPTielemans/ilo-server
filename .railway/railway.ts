// Unverified: written from Railway's Infrastructure as Code docs, never applied.
// Railway builds the Dockerfile without this file, and reads the health check
// and the one replica the relay needs from ../railway.json; this adds Postgres.
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
