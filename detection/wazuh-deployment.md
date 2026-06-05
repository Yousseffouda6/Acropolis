# Acropolis — Phase 4 Wazuh SIEM deployment runbook

This runbook stands up a **Wazuh single-node** SIEM on its own cloud VM (Docker
Compose), locks it down so nothing is internet-exposed, and enrolls a Wazuh
**agent** on the Phase 3 Acropolis host. The reasoning — why the SIEM lives on a
separate box and how the network model works — is in
[`../writeups/phase-4-blueteam.md`](../writeups/phase-4-blueteam.md); this file is
the how-to.

> **Placeholders — never commit real values.**
> `<SIEM_PUBLIC_IP>` = the SIEM instance's public IP (SSH only) ·
> `<SIEM_PRIVATE_IP>` = the SIEM's VPC-private IP (the agent points here) ·
> `<AGENT_PRIVATE_IP>` = the Acropolis host's VPC-private IP ·
> `<SIEM_SG_ID>` = the SIEM security group ID ·
> `<KEY>.pem` = your SSH private key · `<YOUR_IP>` = your workstation's public IP
> (`curl -s https://checkip.amazonaws.com`). `*.pem` / `*.key` are gitignored.

---

## 0. What we build

| | |
| --- | --- |
| Provider / type | AWS EC2 `m7i-flex.large` (8 GB RAM, free-tier eligible) |
| OS / disk | Ubuntu, **30 GB** root EBS (not the 8 GB default — see step 1) |
| Placement | Same VPC as the Acropolis host, **different Availability Zone**, `eu-central-1` |
| Stack | Wazuh single-node via Docker Compose, pinned to `v4.14.5` |
| Dashboard | HTTPS/443 (self-signed) — **not** opened; reached via SSH tunnel |
| Agent ports | `1514`/`1515` opened **only** to `<AGENT_PRIVATE_IP>/32` |
| SSH | `22` from `<YOUR_IP>/32` only; key-only, non-root sudo user |

---

## 1. Provision the SIEM instance

In the EC2 console (or CLI), launch:

- **Type:** `m7i-flex.large` (8 GB RAM). *Do not pick `t3.medium`* — under the AWS
  **Free Plan** non-free-tier types are blocked at launch; `m7i-flex.large` is
  free-tier eligible and has the RAM the indexer needs.
- **OS:** Ubuntu (latest LTS).
- **Disk:** set the root EBS volume to **30 GB**. The 8 GB default fills while
  pulling the Wazuh images (see step 8 if you hit this on an already-running box).
- **Network:** the **same VPC** as the Acropolis host, but a **different
  Availability Zone**. This lets the two talk over private IPs while surviving a
  single-AZ outage.
- **Key pair:** reuse or create one; download `<KEY>.pem`, keep it off version
  control (`*.pem` is gitignored), and `chmod 600` it.
- **Security group:** create a new one (configured in step 6). Do not accept any
  wizard suggestion to open 443/1514/1515 to the world.

Note the instance's **private** IP (`<SIEM_PRIVATE_IP>`) — the agent will point at
it — and its public IP (`<SIEM_PUBLIC_IP>`) for SSH.

---

## 2. First connection

```bash
chmod 600 <KEY>.pem
ssh -i <KEY>.pem ubuntu@<SIEM_PUBLIC_IP>
```

You land as the non-root `ubuntu` user (sudo-capable); the key is the only
credential.

---

## 3. Prerequisites: Docker, Compose, and vm.max_map_count

```bash
# Docker engine + compose plugin
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 git
sudo systemctl enable --now docker

# OpenSearch (the Wazuh indexer) requires a raised mmap limit, or it won't start.
sudo sysctl -w vm.max_map_count=262144
# persist across reboots:
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

---

## 4. Clone wazuh-docker and pin a real version tag

The `stable` branch was retired — clone, then check out an explicit release tag so
the build is reproducible.

```bash
git clone https://github.com/wazuh/wazuh-docker.git ~/wazuh-docker
cd ~/wazuh-docker
git checkout v4.14.5          # pin a version; never a moving branch
cd single-node
```

---

## 5. Generate certificates, then bring the stack up

Wazuh ships a one-shot container that generates the internal TLS certs (indexer ↔
manager ↔ dashboard). Run it once, then start the three services.

```bash
# 5a. generate certs (run once)
sudo docker compose -f generate-indexer-certs.yml run --rm generator

# 5b. start manager + indexer + dashboard
sudo docker compose up -d

# 5c. watch it come up (indexer first, then manager, then dashboard)
sudo docker compose ps
sudo docker compose logs -f wazuh.dashboard   # Ctrl-C once it reports listening
```

> The default dashboard credentials are set in the Compose `.env` / config. Change
> them from the defaults before going further; treat them as a secret (never
> commit them).

Confirm the dashboard is bound and the containers are healthy:

```bash
sudo docker ps --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
# expect: wazuh.manager, wazuh.indexer, wazuh.dashboard all Up;
#         dashboard publishing 443/tcp
```

---

## 6. Security group: scope every port, expose nothing publicly

The SIEM is high value — lock it down like the Phase 3 target. **Three** inbound
rules, no `0.0.0.0/0` anywhere.

```bash
# SSH from your workstation only
aws ec2 authorize-security-group-ingress --region eu-central-1 \
  --group-id <SIEM_SG_ID> --protocol tcp --port 22 --cidr <YOUR_IP>/32

# Agent events + enrollment from the Acropolis host's PRIVATE IP only
aws ec2 authorize-security-group-ingress --region eu-central-1 \
  --group-id <SIEM_SG_ID> --protocol tcp --port 1514 --cidr <AGENT_PRIVATE_IP>/32
aws ec2 authorize-security-group-ingress --region eu-central-1 \
  --group-id <SIEM_SG_ID> --protocol tcp --port 1515 --cidr <AGENT_PRIVATE_IP>/32

# NOTE: there is deliberately NO rule for tcp/443. The dashboard is reached
# only over an SSH tunnel (step 7). Egress stays at the default (allow all).
```

Verify — expect exactly 22 (your IP), 1514 and 1515 (the agent's private IP), and
**no** 443:

```bash
aws ec2 describe-security-groups --group-ids <SIEM_SG_ID> \
  --query 'SecurityGroups[0].IpPermissions'
```

---

## 7. Access the dashboard via SSH tunnel

The dashboard has no public port. Forward 443 to your workstation over SSH:

```bash
ssh -i <KEY>.pem -L 8443:localhost:443 ubuntu@<SIEM_PUBLIC_IP>
```

Leave that session open and browse **https://localhost:8443**. Accept the
self-signed certificate warning (the cert is only ever presented over this already
-authenticated SSH channel). Log in with your (changed) dashboard credentials.

Sanity check from your workstation that the dashboard is **not** directly
reachable:

```bash
curl -m 5 -k https://<SIEM_PUBLIC_IP>/   # expect a timeout / connection refused
```

---

## 8. (If needed) grow the disk live

If the 8 GB default filled mid-pull, expand without rebuilding: grow the EBS volume
in the EC2 console (e.g. to 30 GB), then on the host extend the partition and
filesystem.

```bash
lsblk                                 # identify the root disk/partition, e.g. nvme0n1p1
sudo growpart /dev/nvme0n1 1          # grow the partition to fill the disk
sudo resize2fs /dev/nvme0n1p1         # grow the ext4 filesystem
df -h /                               # confirm the new size
```

No reboot, no data loss; re-run `docker compose up -d` if a pull was interrupted.

---

## 9. Enroll the agent on the Acropolis host

In the dashboard: **Agents → Deploy new agent**. Choose the Linux/DEB package,
**set the manager address to `<SIEM_PRIVATE_IP>`** (the private IP, so traffic
stays in the VPC), and copy the generated install command.

Then, on the **Acropolis host** (the Phase 3 box, over its own SSH):

```bash
# install + register the agent (command comes from the wizard; shape shown here)
sudo WAZUH_MANAGER='<SIEM_PRIVATE_IP>' apt-get install -y wazuh-agent   # via the wizard's repo step
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent --no-pager
```

Back in the dashboard, the new agent should appear **Active** within a minute. It
now ships FIM (`syscheckd`), logs (`logcollector`), vuln/config (`modulesd`), and
active-response (`execd`) telemetry to the manager.

---

## 10. Operational notes

- **Stop / start the stack:** from `~/wazuh-docker/single-node`,
  `sudo docker compose down` / `sudo docker compose up -d`.
- **Logs:** `sudo docker compose logs -f wazuh.manager` (analysis) or
  `wazuh.indexer` (storage).
- **Agent health:** dashboard **Agents** page, or on the target
  `sudo systemctl status wazuh-agent`.
- **Do not** open 443/1514/1515 to `0.0.0.0/0`. The dashboard stays tunnel-only;
  the agent ports stay scoped to `<AGENT_PRIVATE_IP>/32`. Widening any of these
  puts the lab's security record on the open internet.
- **Secrets:** dashboard credentials and any generated certs are **not** committed.
  `*.pem` / `*.key` are gitignored; keep the rest off version control too.
