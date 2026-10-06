# Package signing

Release builds of the Arch package are signed with a GPG key. `pacman -U <url>`
downloads `<url>.sig` and refuses the package if that file is missing or does
not match a trusted key.

The **Publish release** job in `.github/workflows/packages.yml` signs the
package. It runs only for `v*` tags. Packages from `main` and pull requests are
not signed. The key is used only in that job, so jobs that run cargo build
scripts never see it.

## Create the key

Create a dedicated key with no passphrase. Use a temporary GPG home so the key
never enters your own keyring:

```sh
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key \
  'cheesecloth packages <janderson@janderson.ca>' ed25519 sign never
```

Commit the public key:

```sh
gpg --armor --export > packaging/arch/signing-key.asc
```

Store the private key as the `ARCH_SIGNING_KEY` repository secret:

```sh
gpg --armor --export-secret-keys | gh secret set ARCH_SIGNING_KEY
```

Note the fingerprint. Users need it to trust the key:

```sh
gpg --fingerprint
```

Delete the temporary GPG home. The secret is now the only copy of the private
key:

```sh
rm -rf "$GNUPGHOME"
unset GNUPGHOME
```

If the secret is not set, the release job fails. A release is never published
without a signature.

## Trust the key

Do this once on each machine that installs the package:

```sh
sudo pacman-key --add packaging/arch/signing-key.asc
sudo pacman-key --lsign-key <fingerprint>
```

Then install from the release URL:

```sh
sudo pacman -U https://github.com/jdpanderson/cheesecloth-rs/releases/download/<tag>/<package>.pkg.tar.zst
```

## Replace the key

The key has no passphrase, so the GitHub secret is its only protection. If the
secret may have leaked, or to rotate the key:

1. Create a new key as described above. Replace
   `packaging/arch/signing-key.asc` and the `ARCH_SIGNING_KEY` secret.
2. On each machine, remove the old key and trust the new one:

   ```sh
   sudo pacman-key --delete <old fingerprint>
   sudo pacman-key --add packaging/arch/signing-key.asc
   sudo pacman-key --lsign-key <new fingerprint>
   ```

Packages signed with the old key no longer install after the old key is
removed.
