#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
用法：
  ./docker/docker_lab.sh daemon
  ./docker/docker_lab.sh build
  ./docker/docker_lab.sh deploy-realcase <domain> [options]
  ./docker/docker_lab.sh repair-realcase <domain> [options]
  ./docker/docker_lab.sh build-scenario <scenario>
  ./docker/docker_lab.sh build-all-scenarios
  ./docker/docker_lab.sh demo <scenario>
  ./docker/docker_lab.sh run-scenario <scenario>
  ./docker/docker_lab.sh run-all-scenarios
  ./docker/docker_lab.sh shell
  ./docker/docker_lab.sh clean

独立错误镜像场景：
  algorithm-not-recommended
  algorithm-not-supported
  algorithm-prohibited
  bad-ds
  expired-rrsig
  future-rrsig
  expiration-within-clock-skew
  inception-within-clock-skew
  missing-rrsig
  signature-invalid
  missing-ksk
  dnskey-bad-length-ecdsa256
  dnskey-bad-length-ecdsa384
  dnskey-bad-length-ed25519
  dnskey-bad-length-ed448
  dnskey-revoked-rrsig
  dnskey-revoked-ds
  existing-type-not-in-bitmap
  missing-rrsig-for-alg-dnskey
  missing-nsec-for-nxdomain
  missing-nsec-for-nodata
  stype-in-bitmap
  referral-with-ds
  referral-with-soa
  referral-without-ns
  last-nsec-next-not-zone
  sname-not-covered
  nonzero-nsec3-iteration-count
  no-closest-encloser
  no-nsec3-matching-sname
  no-nsec-matching-sname
  no-trust-anchor-signing
  original-ttl-exceeded-rrset
  original-ttl-exceeded-rrsig
  rrsig-labels-exceed-owner-labels
  rrset-ttl-mismatch
  signer-not-zone
  ttl-beyond-expiration
  cds-inconsistent-with-ds
  cdnskey-inconsistent-with-ds
  cdnskey-inconsistent-with-cds
  cds-signer-invalid
  cdnskey-signer-invalid
  cname-loop
  digest-algorithm-not-supported
  ds-digest-algorithm-prohibited
  ds-digest-algorithm-maybe-ignored

示例：
  ./docker/docker_lab.sh daemon   # 仅在当前这类无 systemd 的开发机里需要
  ./docker/docker_lab.sh build
  ./docker/docker_lab.sh deploy-realcase example.org --allow-partial-records
  ./docker/docker_lab.sh repair-realcase dnssec-failed.org --allow-partial-records
  ./docker/docker_lab.sh build-all-scenarios
  ./docker/docker_lab.sh run-scenario bad-ds
EOF
}

SCENARIOS=(
  algorithm-not-recommended
  algorithm-not-supported
  algorithm-prohibited
  bad-ds
  expired-rrsig
  future-rrsig
  expiration-within-clock-skew
  inception-within-clock-skew
  missing-rrsig
  signature-invalid
  missing-ksk
  dnskey-bad-length-ecdsa256
  dnskey-bad-length-ecdsa384
  dnskey-bad-length-ed25519
  dnskey-bad-length-ed448
  dnskey-revoked-rrsig
  dnskey-revoked-ds
  existing-type-not-in-bitmap
  missing-rrsig-for-alg-dnskey
  missing-nsec-for-nxdomain
  missing-nsec-for-nodata
  stype-in-bitmap
  referral-with-ds
  referral-with-soa
  referral-without-ns
  last-nsec-next-not-zone
  sname-not-covered
  nonzero-nsec3-iteration-count
  no-closest-encloser
  no-nsec3-matching-sname
  no-nsec-matching-sname
  no-trust-anchor-signing
  original-ttl-exceeded-rrset
  original-ttl-exceeded-rrsig
  rrsig-labels-exceed-owner-labels
  rrset-ttl-mismatch
  signer-not-zone
  ttl-beyond-expiration
  wildcard-not-covered
  wildcard-covered
  cds-inconsistent-with-ds
  cdnskey-inconsistent-with-ds
  cdnskey-inconsistent-with-cds
  cds-signer-invalid
  cdnskey-signer-invalid
  cname-loop
  digest-algorithm-not-supported
  ds-digest-algorithm-prohibited
  ds-digest-algorithm-maybe-ignored
)

docker_base() {
  if ! docker info >/dev/null 2>&1; then
    if sudo -n docker info >/dev/null 2>&1; then
      echo "sudo docker"
      return
    fi
    cat >&2 <<'EOF'
Docker daemon 当前不可用。

如果是在普通 Linux 主机上，请先启动 Docker 服务，例如：
  sudo systemctl start docker

如果是在当前这种无 systemd 的开发机里，可以尝试：
  ./docker/docker_lab.sh daemon

注意：当前开发机可能不允许 Docker-in-Docker。即使 daemon 能启动，build 仍可能因为外层 namespace/capability 限制失败。
EOF
    exit 1
  fi
  echo "docker"
}

docker_cmd() {
  local base
  base="$(docker_base)"
  # shellcheck disable=SC2086
  $base "$@"
}

valid_scenario() {
  local scenario="$1"
  local item
  for item in "${SCENARIOS[@]}"; do
    if [[ "$item" == "$scenario" ]]; then
      return 0
    fi
  done
  return 1
}

scenario_image() {
  echo "dnssec-error-$1:latest"
}

scenario_container() {
  echo "dnssec-error-$1"
}

require_scenario() {
  local scenario="$1"
  if [[ -z "$scenario" ]] || ! valid_scenario "$scenario"; then
    echo "未知或缺失场景：${scenario:-<empty>}" >&2
    usage
    exit 1
  fi
}

build_base_image() {
  docker_cmd build -f docker/Dockerfile -t dnssec-local-lab:latest .
}

build_scenario_image() {
  local scenario="$1"
  require_scenario "$scenario"
  docker_cmd build \
    -f docker/Dockerfile.scenario \
    --build-arg BASE_IMAGE=dnssec-local-lab:latest \
    --build-arg SCENARIO="$scenario" \
    -t "$(scenario_image "$scenario")" \
    .
}

run_scenario_image() {
  local scenario="$1"
  require_scenario "$scenario"
  local workdir="$PWD/work-docker/$scenario"
  mkdir -p "$workdir"
  docker_cmd run --rm \
    --name "$(scenario_container "$scenario")" \
    --cap-add NET_ADMIN \
    -v "$workdir:/app/dnssec-local-lab/work" \
    -w /app/dnssec-local-lab \
    "$(scenario_image "$scenario")"
}

run_bind_container() {
  mkdir -p work-docker realcase-live-docker
  docker_cmd run --rm \
    --cap-add NET_ADMIN \
    -v "$PWD/work-docker:/app/dnssec-local-lab/work" \
    -v "$PWD/realcase-live-docker:/app/dnssec-local-lab/realcase-live" \
    -w /app/dnssec-local-lab \
    --entrypoint python3 \
    dnssec-local-lab:latest "$@"
}

cmd="${1:-}"
case "$cmd" in
  daemon)
    if docker info >/dev/null 2>&1 || sudo -n docker info >/dev/null 2>&1; then
      echo "Docker daemon 已可用。"
      exit 0
    fi
    echo "尝试启动 dockerd。日志：/tmp/dnssec-lab-dockerd.log"
    sudo dockerd --iptables=false --ip-masq=false --storage-driver=vfs \
      > /tmp/dnssec-lab-dockerd.log 2>&1 &
    sleep 3
    if sudo -n docker info >/dev/null 2>&1; then
      echo "Docker daemon 已启动。"
      echo "如果后续 build 报 mount namespace/pivot 权限错误，说明当前开发机不支持 Docker-in-Docker。"
    else
      echo "Docker daemon 启动失败，最近日志如下：" >&2
      tail -80 /tmp/dnssec-lab-dockerd.log >&2 || true
      exit 1
    fi
    ;;
  build)
    build_base_image
    ;;
  deploy-realcase)
    domain="${2:-}"
    if [[ -z "$domain" ]]; then
      echo "缺少 domain，例如：./docker/docker_lab.sh deploy-realcase example.org" >&2
      exit 1
    fi
    run_bind_container dnssec_repair_engine.py deploy-realcase --backend bind9 --domain "$domain" "${@:3}"
    ;;
  repair-realcase)
    domain="${2:-}"
    if [[ -z "$domain" ]]; then
      echo "缺少 domain，例如：./docker/docker_lab.sh repair-realcase dnssec-failed.org" >&2
      exit 1
    fi
    run_bind_container dnssec_lab.py repair-realcase --backend bind9 --domain "$domain" "${@:3}"
    ;;
  build-scenario)
    scenario="${2:-}"
    build_scenario_image "$scenario"
    ;;
  build-all-scenarios)
    build_base_image
    for scenario in "${SCENARIOS[@]}"; do
      echo "构建独立错误镜像：$(scenario_image "$scenario")"
      build_scenario_image "$scenario"
    done
    ;;
  demo)
    scenario="${2:-}"
    require_scenario "$scenario"
    mkdir -p work-docker realcase-live-docker
    docker_cmd run --rm \
      --cap-add NET_ADMIN \
      -v "$PWD/work-docker:/app/dnssec-local-lab/work" \
      -v "$PWD/realcase-live-docker:/app/dnssec-local-lab/realcase-live" \
      -w /app/dnssec-local-lab \
      dnssec-local-lab:latest demo "$scenario"
    ;;
  run-scenario)
    scenario="${2:-}"
    run_scenario_image "$scenario"
    ;;
  run-all-scenarios)
    for scenario in "${SCENARIOS[@]}"; do
      echo "运行独立错误容器：$(scenario_container "$scenario")"
      run_scenario_image "$scenario"
    done
    ;;
  shell)
    mkdir -p work-docker realcase-live-docker
    docker_cmd run --rm -it \
      --cap-add NET_ADMIN \
      -v "$PWD/work-docker:/app/dnssec-local-lab/work" \
      -v "$PWD/realcase-live-docker:/app/dnssec-local-lab/realcase-live" \
      -w /app/dnssec-local-lab \
      --entrypoint bash \
      dnssec-local-lab:latest -l
    ;;
  clean)
    docker_cmd rm -f dnssec-local-lab 2>/dev/null || true
    for scenario in "${SCENARIOS[@]}"; do
      docker_cmd rm -f "$(scenario_container "$scenario")" 2>/dev/null || true
    done
    rm -rf work-docker realcase-live-docker
    ;;
  ""|-h|--help|help)
    usage
    ;;
  *)
    echo "未知命令：$cmd" >&2
    usage
    exit 1
    ;;
esac
