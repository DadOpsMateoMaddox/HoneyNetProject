Dev Container for CerberusMesh

Quick start
1. In VS Code, install the Remote - Containers extension.
2. Open this repository in VS Code.
3. When prompted, click "Reopen in Container". The container will build and run the `post-create.sh` script which installs AWS CLI, SAM CLI, and GitHub CLI.

AWS credentials options
- Recommended (safe/easy): Run `aws configure --profile honeypot-team` inside the container and use that profile for commands.
- Alternative (convenient on a personal machine): Uncomment the mounts line in `.devcontainer/devcontainer.json` to bind your host `~/.aws` into the container. Only do this on trusted machines.

Verify the container has credentials and can call AWS:

```sh
aws sts get-caller-identity --profile honeypot-team
```

If the command returns an ARN and account id, you are authenticated.

Security notes
- Do not commit any private keys, `.pem`, `.key`, or the `secrets/` folder into git.
- Use the provided `scripts/generate_keys.sh` to generate local SSH keys and certs.

Ports
- The container forwards ports 3000, 8000, and 9090 by default. Adjust in `devcontainer.json` if your services use different ports.

If you want me to also add an example task that launches Cowrie or a small honeypot container inside the devcontainer (using Docker socket), say so and I’ll add it.
