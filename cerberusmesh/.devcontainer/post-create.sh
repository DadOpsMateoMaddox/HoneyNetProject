#!/usr/bin/env bash
set -eux

# update
sudo apt-get update -y
sudo apt-get install -y curl unzip jq less git build-essential

# AWS CLI v2
if ! command -v aws >/dev/null 2>&1; then
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp
  sudo /tmp/aws/install
  rm -rf /tmp/aws /tmp/awscliv2.zip
fi

# SAM CLI (lightweight install)
if ! command -v sam >/dev/null 2>&1; then
  sudo apt-get install -y python3 python3-pip
  pip3 install --user aws-sam-cli
  echo 'export PATH=$HOME/.local/bin:$PATH' >> /home/vscode/.bashrc
fi

# GitHub CLI (optional)
if ! command -v gh >/dev/null 2>&1; then
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | \
    sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
  sudo apt-get update
  sudo apt-get install -y gh
fi

# verify minimal tools
aws --version || true
sam --version || true
gh --version || true

cat <<'EOF'
Devcontainer: setup complete.
- If you want the container to use your local AWS credentials, re-open this folder in container with
  the recommended bind mount commented in .devcontainer/devcontainer.json (or run `aws configure` inside).
- Test with:
  aws sts get-caller-identity
EOF
