#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
用法：
  ./docker/powerdns_docker_lab.sh daemon
  ./docker/powerdns_docker_lab.sh build
  ./docker/powerdns_docker_lab.sh build-scenario <scenario>
  ./docker/powerdns_docker_lab.sh build-all-scenarios
  ./docker/powerdns_docker_lab.sh demo <scenario>
  ./docker/powerdns_docker_lab.sh run-scenario <scenario>
  ./docker/powerdns_docker_lab.sh run-all-scenarios
  ./docker/powerdns_docker_lab.sh shell
  ./docker/powerdns_docker_lab.sh clean

说明：
  该脚本使用 PowerDNS Authoritative + bind backend 作为权威服务器，
  继续复用现有 DNSSEC zone 生成、DNSViz 诊断和本地修复流程。

示例：
  ./docker/powerdns_docker_lab.sh build
  ./docker/powerdns_docker_lab.sh build-scenario bad-ds
  ./docker/powerdns_docker_lab.sh run-scenario bad-ds
EOF
}

scenario_list() {
  python3 - <<'PY'
from dnssec_scenarios import names
for name in names():
    print(name)
PY
}

valid_scenario() {
  local scenario="$1"
  [[ -n "$scenario" ]] || return 1
  scenario_list | grep -Fxq "$scenario"
}

docker_base() {
  if ! docker info >/dev/null 2>&1; then
    if sudo -n docker info >/dev/null 2>&1; then
      echo "sudo docker"
      return
    fi
    cat >&2 <<'EOF'
Docker daemon 当前不可用。

普通 Linux 主机：
  sudo systemctl start docker

当前这类无 systemd 的开发机：
  ./docker/powerdns_docker_lab.sh daemon

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

require_scenario() {
  local scenario="$1"
  if ! valid_scenario "$scenario"; then
    echo "未知或缺失场景：${scenario:-<empty>}" >&2
    usage
    exit 1
  fi
}

scenario_image() {
  echo "dnssec-powerdns-error-$1:latest"
}

scenario_container() {
  echo "dnssec-powerdns-error-$1"
}

build_base_image() {
  docker_cmd build -f docker/Dockerfile.powerdns -t dnssec-powerdns-lab:latest ..
}

build_scenario_image() {
  local scenario="$1"
  require_scenario "$scenario"
  docker_cmd build \
    -f docker/Dockerfile.powerdns.scenario \
    --build-arg BASE_IMAGE=dnssec-powerdns-lab:latest \
    --build-arg SCENARIO="$scenario" \
    -t "$(scenario_image "$scenario")" \
    .
}

run_scenario_image() {
  local scenario="$1"
  require_scenario "$scenario"
  local workdir="$PWD/work-powerdns-docker/$scenario"
  mkdir -p "$workdir"
  docker_cmd run --rm \
    --name "$(scenario_container "$scenario")" \
    --cap-add NET_ADMIN \
    -v "$workdir:/app/dnssec-local-lab/work" \
    -w /app/dnssec-local-lab \
    "$(scenario_image "$scenario")"
}

cmd="${1:-}"
case "$cmd" in
  daemon)
    if docker info >/dev/null 2>&1 || sudo -n docker info >/dev/null 2>&1; then
      echo "Docker daemon 已可用。"
      exit 0
    fi
    echo "尝试启动 dockerd。日志：/tmp/dnssec-powerdns-dockerd.log"
    sudo dockerd --iptables=false --ip-masq=false --storage-driver=vfs \
      > /tmp/dnssec-powerdns-dockerd.log 2>&1 &
    sleep 3
    if sudo -n docker info >/dev/null 2>&1; then
      echo "Docker daemon 已启动。"
      echo "如果后续 build 报 mount namespace/pivot 权限错误，说明当前开发机不支持 Docker-in-Docker。"
    else
      echo "Docker daemon 启动失败，最近日志如下：" >&2
      tail -80 /tmp/dnssec-powerdns-dockerd.log >&2 || true
      exit 1
    fi
    ;;
  build)
    build_base_image
    ;;
  build-scenario)
    build_scenario_image "${2:-}"
    ;;
  build-all-scenarios)
    build_base_image
    while IFS= read -r scenario; do
      echo "构建 PowerDNS 独立错误镜像：$(scenario_image "$scenario")"
      build_scenario_image "$scenario"
    done < <(scenario_list)
    ;;
  demo)
    scenario="${2:-}"
    require_scenario "$scenario"
    mkdir -p work-powerdns-docker
    docker_cmd run --rm \
      --cap-add NET_ADMIN \
      -v "$PWD/work-powerdns-docker:/app/dnssec-local-lab/work" \
      -w /app/dnssec-local-lab \
      dnssec-powerdns-lab:latest demo "$scenario"
    ;;
  run-scenario)
    run_scenario_image "${2:-}"
    ;;
  run-all-scenarios)
    while IFS= read -r scenario; do
      echo "运行 PowerDNS 独立错误容器：$(scenario_container "$scenario")"
      run_scenario_image "$scenario"
    done < <(scenario_list)
    ;;
  shell)
    mkdir -p work-powerdns-docker
    docker_cmd run --rm -it \
      --cap-add NET_ADMIN \
      -v "$PWD/work-powerdns-docker:/app/dnssec-local-lab/work" \
      -w /app/dnssec-local-lab \
      --entrypoint bash \
      dnssec-powerdns-lab:latest -l
    ;;
  clean)
    docker_cmd rm -f dnssec-powerdns-lab 2>/dev/null || true
    while IFS= read -r scenario; do
      docker_cmd rm -f "$(scenario_container "$scenario")" 2>/dev/null || true
    done < <(scenario_list)
    rm -rf work-powerdns-docker
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
