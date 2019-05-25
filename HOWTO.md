# HOWTO #

### Using git from the board ###

Interacting with the git repo from the board is straightforward, once
you've configured `git` properly. Here are the steps:

1. Ensure you have the keypair macula-vmi-git[.pub]. It's on the board under /home/matt.

2. Clone the repo, pointing the command to your own copy of the key. For instance:
   ```bash
   $	GIT_SSH_COMMAND="ssh -i /home/matt/public-git-key/macula-vmi-git"   git clone git@bitbucket.org:macula/vmi.git
   ```

3. Configure `git` to use your key for the repo thereafter:
   ```bash
   $   cd vmi
   $   git config core.sshCommand 'ssh -i /home/matt/public-git-key/macula-vmi-git`
   ```bash

The key should provide you with read-only access to the repo.