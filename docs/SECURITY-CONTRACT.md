# Agent security contract

## What acceptance means

A valid Agent report proves that a holder of the session key signed the canonical report, the report was bound to the expected session and fresh challenge, and its sequence and digest chain were accepted. It does not prove the observations are honest or that the client is cheat-free.

The authoritative game server remains responsible for every gameplay mutation. Client-only Agent evidence cannot independently punish an account.

## Collection boundary

The default collectors are limited to approved build-file hashes, executable identity, process relationship, loaded image basenames, debugger observation, probe health, and timestamps. The Agent does not inspect unrelated processes or collect raw memory, arbitrary files, usernames, email addresses, command lines, keystrokes, screenshots, window titles, or network history.

## Deployment modes

- Required: ranked and protected-economy sessions may require a healthy Agent.
- Optional: casual sessions may continue in a degraded classification.
- Disabled: offline play never requires Agent connectivity.

Unexpected modules and debugger observations are advisory. A game may reject admission when the Agent itself is missing, revoked, expired, or cryptographically invalid, but it must not translate an advisory observation directly into an account ban.

