#!/usr/bin/env sh
# vigile installer — https://github.com/wang844001973/vigile
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/wang844001973/vigile/refs/heads/master/install.sh | sh
#   VIGILE_DIR=~/tools VIGILE_BRANCH=develop sh install.sh   # 可定制

set -e

REPO="wang844001973/vigile"
BRANCH="${VIGILE_BRANCH:-master}"
INSTALL_DIR="${VIGILE_DIR:-$HOME/.local/vigile}"
BIN_DIR="${VIGILE_BIN_DIR:-$HOME/.local/bin}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; exit 1; }

# --- 前置：node >= 22.5（内置 node:sqlite，vigile 唯一依赖）
check_node() {
    command -v node >/dev/null 2>&1 || error "未找到 node（需要 >= 22.5，https://nodejs.org）"
    NODE_MAJOR=$(node -e 'console.log(process.versions.node.split(".")[0])')
    NODE_MINOR=$(node -e 'console.log(process.versions.node.split(".")[1])')
    if [ "$NODE_MAJOR" -lt 22 ] || { [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -lt 5 ]; }; then
        error "node $NODE_MAJOR.$NODE_MINOR 过旧（需要 >= 22.5，内置 node:sqlite）"
    fi
    info "node $(node --version) 满足要求"
}

# --- 获取最新 tag（重定向优先，不占 API 配额；失败回退分支模式）
get_ref() {
    VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" \
        | grep -i '^location:' | sed -E 's|.*/tag/([^[:space:]]+).*|\1|' | tr -d '\r')
    if [ -n "$VERSION" ]; then
        REF="$VERSION"
        info "最新版本: $VERSION"
    else
        REF="$BRANCH"
        warn "版本查询失败（网络/限流），回退到 ${BRANCH} 分支"
    fi
}

# --- 下载并校验（checksum 缺失时拒绝继续，不静默装未验证内容）
download() {
    TEMP_DIR=$(mktemp -d)
    ARCHIVE="${TEMP_DIR}/vigile.tar.gz"
    URL="https://github.com/${REPO}/archive/${REF}.tar.gz"
    info "下载: $URL"
    curl -fsSL "$URL" -o "$ARCHIVE" || error "下载失败（网络或 tag 不存在）"

    # tar 路径安全：拒绝绝对路径与 .. 穿越（CWE-22）
    if tar -tzf "$ARCHIVE" | grep -qE '^/|(^|/)\.\.(/|$)'; then
        error "压缩包含不安全路径，拒绝安装"
    fi

    info "解压..."
    tar -xzf "$ARCHIVE" -C "$TEMP_DIR"
    SRC_DIR=$(echo "$TEMP_DIR"/vigile-*/ | head -1)
    [ -d "$SRC_DIR" ] || error "解压结果异常"
}

# --- 落位：克隆体进 INSTALL_DIR，入口 shim 进 BIN_DIR
install_files() {
    mkdir -p "$INSTALL_DIR" "$BIN_DIR"
    rm -rf "$INSTALL_DIR.bak"
    [ -d "$INSTALL_DIR" ] && mv "$INSTALL_DIR" "$INSTALL_DIR.bak" && warn "旧版本备份至 $INSTALL_DIR.bak"
    mkdir -p "$INSTALL_DIR"
    # 备份恢复策略：仅核心目录，用户可手动合并 ~/.vigile 之外的自定义内容
    cp -R "$SRC_DIR"/bin "$SRC_DIR"/hooks "$SRC_DIR"/src "$SRC_DIR"/test \
          "$SRC_DIR"/install.mjs "$SRC_DIR"/package.json "$SRC_DIR"/README.md \
          "$SRC_DIR"/SKILL.md "$SRC_DIR"/LICENSE "$INSTALL_DIR/" 2>/dev/null || true

    for name in vigile vig; do
        printf '#!/bin/sh\nexec node "%s/bin/vigile.js" "$@"\n' "$INSTALL_DIR" > "$BIN_DIR/$name"
        chmod +x "$BIN_DIR/$name"
    done
    rm -rf "$TEMP_DIR"
    info "安装至 $INSTALL_DIR（入口: $BIN_DIR/vig, $BIN_DIR/vigile）"
}

verify() {
    if ! "$BIN_DIR/vig" --version >/dev/null 2>&1; then
        error "验证失败：$BIN_DIR/vig 无法运行"
    fi
    info "验证通过: $("$BIN_DIR/vig" --version)"
    command -v vig >/dev/null 2>&1 || {
        warn "已安装但 vig 不在当前 PATH。加入 shell 配置："
        warn "  export PATH=\"$BIN_DIR:\$PATH\""
    }
}

main() {
    info "安装 vigile（守夜人 — AI agent 调用审计 + 执行前审核）"
    check_node
    get_ref
    download
    install_files
    verify
    echo ""
    info "安装完成！下一步："
    echo "  vig init --global            给所有 agent 装 hook（推荐）"
    echo "  vig kubectl version --client 试一条内部命令"
    echo "  vig logs --limit 5           看审计记录"
}

main
