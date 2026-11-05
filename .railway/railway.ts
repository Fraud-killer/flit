// Railway infrastructure for FLIT, applied with `railway config plan` and
// `railway config apply` (see docs/deployment.md). This file is the whole
// project: the API, its Postgres and Redis, and the eight scheduled jobs.
//
// Secrets are never written here. SECRET_KEY and MCRYPT_KEY are read from
// the shell when the file is applied (FLIT_SECRET_KEY, FLIT_MCRYPT_KEY) and
// otherwise left exactly as Railway already holds them.

import {
  defineRailway,
  github,
  postgres,
  preserve,
  project,
  redis,
  service,
} from "railway/iac";

const REPO = "Fraud-killer/flit";
const BRANCH = "main";

// The public hosts the API answers on. Fill in after `railway domain` has
// generated one (or a custom domain has been attached) and apply again.
// healthcheck.railway.app is the Host header Railway's health check sends;
// Django returns 400 to a host it does not know, which Railway reads as an
// unhealthy deploy.
const PUBLIC_HOSTS: string[] = ["flit-production.up.railway.app"];
const ALLOWED_HOSTS = JSON.stringify([...PUBLIC_HOSTS, "healthcheck.railway.app"]);
const CSRF_TRUSTED_ORIGINS = JSON.stringify(PUBLIC_HOSTS.map((host) => `https://${host}`));

function secretFromShell(name: string) {
  const value = process.env[name];
  return value && value.length > 0 ? value : preserve();
}

const build = {
  builder: "DOCKERFILE" as const,
  dockerfilePath: "Dockerfile.app",
};

export default defineRailway(() => {
  const db = postgres("postgres");
  const cache = redis("redis");

  const flit = service("flit", {
    source: github(REPO, { branch: BRANCH }),
    build,
    deploy: {
      // No startCommand: the image's CMD (Dockerfile.app) starts daphne on
      // $PORT. Railway runs a startCommand given here without a shell, so
      // "$PORT" would reach daphne as four literal characters.
      // Once per deploy, not once per replica: every replica racing to apply
      // the same schema change is what putting migrate in the start command
      // would mean.
      preDeployCommand: ["python manage.py migrate --no-input"],
      // /health/ is exempt from the HTTPS redirect (kernel.settings), so the
      // check sees the app rather than a 301.
      healthcheckPath: "/health/",
      healthcheckTimeout: 120,
      restartPolicyType: "ON_FAILURE",
      restartPolicyMaxRetries: 3,
    },
    env: {
      DATABASE_URL: db.env.DATABASE_URL,
      REDIS_URL: cache.env.REDIS_URL,
      CACHE_URL: cache.env.REDIS_URL,
      SECRET_KEY: secretFromShell("FLIT_SECRET_KEY"),
      MCRYPT_KEY: secretFromShell("FLIT_MCRYPT_KEY"),
      DEBUG: "False",
      SECURE_SSL_REDIRECT: "True",
      ALLOWED_HOSTS,
      CSRF_TRUSTED_ORIGINS,
      // One balancer appends to X-Forwarded-For before FLIT. Rate limits and
      // the recorded client address use the entry it wrote, not the one the
      // client typed.
      TRUSTED_PROXY_DEPTH: "1",
    },
  });

  // Every job holds a cache lock while it runs (core.services.job_lock) and
  // Railway skips a run whose predecessor is still active, so none of these
  // can overlap itself. Railway's floor is five minutes between runs.
  const jobEnv = {
    DATABASE_URL: db.env.DATABASE_URL,
    REDIS_URL: cache.env.REDIS_URL,
    CACHE_URL: cache.env.REDIS_URL,
    SECRET_KEY: flit.env.SECRET_KEY,
    MCRYPT_KEY: flit.env.MCRYPT_KEY,
    DEBUG: "False",
  };

  function job(name: string, command: string, cronSchedule: string) {
    return service(name, {
      source: github(REPO, { branch: BRANCH }),
      build,
      deploy: {
        startCommand: `python manage.py ${command}`,
        cronSchedule,
        restartPolicyType: "NEVER",
      },
      env: jobEnv,
    });
  }

  const jobs = [
    // Drains the webhook queue. Delivery latency is this interval plus the
    // row's own backoff; the queue is idempotent and safe to overlap.
    job("deliver-webhooks", "deliver_webhooks --limit 200", "*/5 * * * *"),
    job("expire-challenges", "expire_challenges", "*/5 * * * *"),
    // Alert on a non-zero exit: a sanctions list that quietly stopped
    // refreshing is worse than no list.
    job("refresh-sanctions", "refresh_sanctions", "30 3 * * *"),
    // Tor exit nodes and the IP blocklist that IPIntelligence reads from the
    // cache. Without this the Tor and blocklist signals are silently empty.
    job("refresh-threat-intel", "refresh_threat_intel", "15 * * * *"),
    // Learns from the labels that arrived, inside its guardrails.
    job("calibrate", "calibrate --all --apply", "0 2 * * *"),
    // Exits non-zero when a row has been edited or the chain broken. The
    // chain only proves anything if this runs; wire the exit to an alert.
    job("verify-audit-chain", "verify_audit_chain", "0 4 * * *"),
    // Agent FLIT. Both exit at once while AGENT_ENABLED is off. With it on,
    // set AGENT_ENABLED and ANTHROPIC_API_KEY on these two services too.
    job("run-monitors", "run_monitors", "*/5 * * * *"),
    job("run-investigations", "run_investigations --limit 10", "*/5 * * * *"),
  ];

  return project("flit", {
    resources: [db, cache, flit, ...jobs],
  });
});
