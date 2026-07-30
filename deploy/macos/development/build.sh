#!/bin/bash
set -eu
umask 077

usage() {
  echo "usage: build.sh <absolute-empty-build-directory> <absolute-python-repository>" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
build_directory=$1
python_repository=$2
for path in "$build_directory" "$python_repository"; do
  case "$path" in
    /*) ;;
    *) usage ;;
  esac
  case "$path" in
    *"/../"*|*"/./"*|*/..|*/.) usage ;;
  esac
done

[ "$(/usr/bin/uname -s)" = "Darwin" ] || {
  echo "development build is available only on macOS" >&2
  exit 69
}
[ "$(/usr/bin/uname -m)" = "arm64" ] || {
  echo "development build requires arm64 macOS" >&2
  exit 69
}
[ -d "$build_directory" ] && [ ! -L "$build_directory" ] || {
  echo "build directory must be a real directory" >&2
  exit 66
}
[ -d "$python_repository" ] && [ ! -L "$python_repository" ] \
  && [ -f "$python_repository/pyproject.toml" ] \
  && [ -f "$python_repository/scripts/savana_jarvis_python_entry.py" ] || {
  echo "python repository is incomplete" >&2
  exit 66
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
rust_repository=$(CDPATH= cd -- "$script_directory/../../.." && pwd -P)
python_executable="$python_repository/.venv/bin/python"
if [ ! -x "$python_executable" ]; then
  python_git_directory=$(/usr/bin/git -C "$python_repository" rev-parse --git-common-dir)
  case "$python_git_directory" in
    /*) ;;
    *) python_git_directory="$python_repository/$python_git_directory" ;;
  esac
  python_root=$(CDPATH= cd -- "$(dirname -- "$python_git_directory")" && pwd -P)
  python_executable="$python_root/.venv/bin/python"
fi
[ -x "$python_executable" ] || {
  echo "python build environment is unavailable" >&2
  exit 69
}
python_environment=$(CDPATH= cd -- "$(dirname -- "$python_executable")/.." && pwd -P)
"$python_executable" -c "import PyInstaller, maturin" || {
  echo "python build environment requires PyInstaller and maturin" >&2
  exit 69
}

temporary_directory=$(/usr/bin/mktemp -d "/private/tmp/savana-development-build.XXXXXX")
cleanup() {
  /bin/rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

cargo build \
  --manifest-path \
  "$rust_repository/crates/savana-development-audit-bridge/Cargo.toml" \
  --locked \
  --target-dir "$temporary_directory/audit-target" \
  --bins

cargo build \
  --manifest-path "$rust_repository/Cargo.toml" \
  --locked \
  --features macos-development-authority \
  -p savana-kerneld \
  -p savana-agentd \
  -p savana-ingressd \
  -p savana-approvald \
  -p savana-execd \
  -p savana-policy-core \
  -p savana-platform-identity \
  --bins

"$rust_repository/target/debug/savana-development-build-inputs" "$build_directory"
/bin/mkdir "$build_directory/bin" "$build_directory/libexec"

/usr/bin/install -m 0755 \
  "$temporary_directory/audit-target/debug/savana-development-audit-bridge" \
  "$build_directory/bin/savana-development-audit-bridge"
for service in kerneld agentd ingressd approvald execd; do
  /usr/bin/install -m 0755 \
    "$rust_repository/target/debug/savana-$service" \
    "$build_directory/bin/savana-$service"
done
for worker in savana-worker-sandbox savana-parser-worker savana-connector-worker; do
  /usr/bin/install -m 0755 \
    "$rust_repository/target/debug/$worker" \
    "$build_directory/bin/$worker"
done
for helper in savana-development-manifest savana-development-material savana-development-attestation-root savana-macos-code-identity; do
  /usr/bin/install -m 0755 \
    "$rust_repository/target/debug/$helper" \
    "$build_directory/libexec/$helper"
done

/usr/bin/env -u CONDA_PREFIX \
  VIRTUAL_ENV="$python_environment" \
  PATH="$python_environment/bin:$PATH" \
  "$python_executable" -m maturin develop \
  --manifest-path "$python_repository/native/savana_kernel_client/Cargo.toml" \
  --features extension-module,macos-development-authority \
  --locked
PYINSTALLER_CONFIG_DIR="$temporary_directory/pyinstaller" \
  "$python_executable" -m PyInstaller \
  --clean \
  --noconfirm \
  --onefile \
  --name savana-jarvis-python \
  --paths "$python_repository" \
  --collect-all _savana_kernel_client \
  --add-data "$python_repository/server/runtime/tool_packs/secure_pdf_v2.yaml:server/runtime/tool_packs" \
  --exclude-module torch \
  --exclude-module torchvision \
  --exclude-module torchaudio \
  --exclude-module transformers \
  --exclude-module sklearn \
  --exclude-module scipy \
  --exclude-module pandas \
  --exclude-module pyarrow \
  --exclude-module spacy \
  --exclude-module thinc \
  --exclude-module matplotlib \
  --distpath "$temporary_directory/dist" \
  --workpath "$temporary_directory/work" \
  --specpath "$temporary_directory/spec" \
  "$python_repository/scripts/savana_jarvis_python_entry.py"
/usr/bin/install -m 0755 \
  "$temporary_directory/dist/savana-jarvis-python" \
  "$build_directory/bin/savana-jarvis-python"

"$script_directory/validate.sh" "$build_directory"
trap - EXIT HUP INT TERM
cleanup
echo "assembled Savana development build: $build_directory"
