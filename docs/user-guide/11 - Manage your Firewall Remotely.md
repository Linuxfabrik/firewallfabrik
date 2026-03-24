# Manage your Firewall Remotely

This chapter explains how to set up a firewall on a dedicated machine and use a separate workstation to manage it with FirewallFabrik.

## The Management Workstation

The management workstation runs the FirewallFabrik GUI (`fwf`). Follow the installation instructions in [02 - Installing FirewallFabrik](02%20-%20Installing%20FirewallFabrik.md) to install FirewallFabrik.

Once you get the FirewallFabrik GUI up and running on the management workstation, you need to build a firewall policy and, eventually, compile it and install it on the firewall. Other sections of this Guide describe all steps of this process. Configuration of the built-in policy installer and different ways to use it to install and activate generated policy on the dedicated firewall can be found in [10 - Compiling and Installing a Policy](10%20-%20Compiling%20and%20Installing%20a%20Policy.md).

## The Dedicated Firewall Machine

The firewall machine should have a minimal OS installation. A RHEL 8+, AlmaLinux, Rocky Linux, Debian 12+, or Ubuntu 22.04+ server install is recommended. All you need is the Linux kernel, basic tools, and an SSH daemon. Do not install desktop environments or unnecessary software on the firewall.

Once the OS is installed, verify that the SSH daemon is running:

``` bash
systemctl status sshd
```

If it is not running, enable and start it:

``` bash
sudo systemctl enable --now sshd
```

The firewall machine needs iptables or nftables installed, depending on which platform you have configured in FirewallFabrik. On RHEL 8+ and derivatives, nftables is the default; on older systems, iptables is still available.

> [!TIP]
> Disable the distribution's built-in firewall management (e.g. `firewalld` on RHEL/Fedora, `ufw` on Ubuntu) to avoid conflicts with FirewallFabrik-generated scripts:
>
> ``` bash
> # RHEL / Fedora / CentOS
> sudo systemctl disable --now firewalld
>
> # Debian / Ubuntu
> sudo systemctl disable --now ufw
> ```

### SSH Key-Based Authentication

For any deployment workflow -- manual or automated -- SSH key-based authentication is strongly recommended over password authentication. Set it up on the management workstation:

``` bash
# Generate a key pair (if you don't already have one)
ssh-keygen -t ed25519 -C "fwadmin@mgmt"

# Copy the public key to the firewall
ssh-copy-id fwadmin@firewall

# Verify passwordless login
ssh fwadmin@firewall hostname
```

Once key-based auth works, you can optionally disable password authentication in `/etc/ssh/sshd_config` on the firewall for better security:

``` text
PasswordAuthentication no
PubkeyAuthentication yes
```

## Workflows

### Manual Workflow

The simplest workflow for managing a remote firewall is:

1.  Build your firewall policy in the FirewallFabrik GUI on the management workstation.

2.  Compile the policy (`Rules > Compile`). This generates a shell script.

3.  Copy the generated script to the firewall:

    ``` bash
    scp guardian.fw fwadmin@firewall:/etc/firewall/
    ```

4.  Activate the script on the firewall:

    ``` bash
    ssh fwadmin@firewall 'sudo /etc/firewall/guardian.fw'
    ```

5.  Optionally, integrate with systemd so the policy persists across reboots (see [12 - Integration with OS Running on the Firewall Machine](12%20-%20Integration%20with%20OS%20Running%20on%20the%20Firewall%20Machine.md)).

### Git + Ansible Workflow (Recommended)

For production environments, treat your firewall policy as code:

1.  **Version control**: Store your `.fwf` files and generated scripts in a Git repository.
2.  **Edit and compile**: Use the FirewallFabrik GUI to edit the policy and compile it.
3.  **Commit**: Commit both the source `.fwf` file and the generated `.fw` script(s).
4.  **Deploy with Ansible**: Use a playbook to push the generated script and activate it on the firewall.
5.  **Review**: Use pull/merge requests and peer review for policy changes before deploying.

``` text
+-----------+     +--------+     +---------+     +----------+
| Edit in   | --> | Commit | --> | Ansible | --> | Firewall |
| fwf GUI   |     | to Git |     | deploy  |     | machine  |
+-----------+     +--------+     +---------+     +----------+
```

This workflow provides an audit trail (Git history), peer review (merge requests), and repeatable deployments (Ansible).

### CI/CD Pipeline Workflow

For larger environments or teams that already use CI/CD:

1.  **Edit and compile** the policy in the FirewallFabrik GUI.
2.  **Push** the changes to a Git repository (e.g. GitLab, GitHub).
3.  A **CI/CD pipeline** automatically validates the change and deploys it to the target firewall(s).
4.  Use a **manual gate** in the pipeline to require explicit operator approval before deployment.

See [12 - Integration with OS Running on the Firewall Machine](12%20-%20Integration%20with%20OS%20Running%20on%20the%20Firewall%20Machine.md) for example Ansible playbook and CI/CD pipeline configuration.

See [10 - Compiling and Installing a Policy](10%20-%20Compiling%20and%20Installing%20a%20Policy.md) for detailed instructions on compiling policies and using the built-in installer.
