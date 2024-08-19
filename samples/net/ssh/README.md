# SSH Sample

## Setup

```shell
# Start zeth
sudo ./tools/net-tools/net-setup.sh --config zeth.conf start

# Build sample
west build -b native_sim zephyr-ssh/samples/net/ssh

# Run sample
./build/zephyr/zephyr.exe --seed-random
```

Attach to the Zephyr UART shell using your favourite terminal emulator (replace `/dev/pts/12`
with whatever Zephyr printed out above e.g `uart connected to pseudotty: /dev/pts/12`):
```shell
python3 -m serial.tools.miniterm /dev/pts/12 --raw --eol CRLF
```

In Zephyr shell:
```shell
# On the first run; generate and save host keys (host key index 0)
ssh_key gen 0 rsa 2048
ssh_key save 0 priv id_rsa

# On subsequent runs you can instead load the host key (host key index 0)
ssh_key load 0 priv id_rsa
```

## SSH server

In Zephyr shell:
```shell
# Start SSH server (server instance 0, host key index 0)
sshd start 0 192.0.2.1 0 password123
# or bind to "0.0.0.0" if you are feeling brave...
```

In host computer shell:
```shell
# Connect to the Zephyr SSH server from your host computer
ssh zephyr@192.0.2.1

# To exit press 'Enter' then '~' then '.' (i.e. enter tilde dot)
```

## SSH client

In Zephyr shell:
```shell
# Connect to your host computer from the Zephyr SSH client (client instance 0)
# Replace <user-name> with the desired host computer user
# Note: The terminal can still be a little wonky in this direction
ssh start 0 <user-name>@192.0.2.2

# Ctrl+d to exit
```

## Client public key auth

In Zephyr shell:
```shell
# Export the public key (host key index 0)
ssh_key pub export 0
```

In host computer shell:
```shell
# Convert the exported key to RFC4716 format and add to authorized_keys
ssh-keygen -i -f /dev/stdin -m pkcs8 <<< \
'-----BEGIN PUBLIC KEY-----
<your base-64 encoded host key>
-----END PUBLIC KEY-----' \
>> ~/.ssh/authorized_keys
```

In Zephyr shell:
```shell
# Restart ssh client with extra host key argument, no password needed!
# (client instance 0, host key index 0)
ssh stop 0
ssh start 0 <user-name>@192.0.2.2 0
```

## Server public key auth

In host computer shell:
```shell
# Convert computer public key to PEM
ssh-keygen -e -f ~/.ssh/id_rsa.pub -m pem
```

In Zephyr shell:
```shell
# Import the public key (host key index 1)
ssh_key pub import 1
# Paste the output from above, followed by Ctrl+C

# Save the public key (host key index 1)
ssh_key save 1 pub authorized_key_0

# On subsequent runs you can instead load the public host key
ssh_key load 1 pub authorized_key_0

# Restart ssh server with no password (disabled) and authorized key argument
# (server instance 0, host key index 0, port 22, authorized host key index 1)
sshd stop 0
sshd start 0 192.0.2.1 0 '' 22 1
```

In host computer shell:
```shell
# Connect to the Zephyr SSH server from your host computer, no password needed!
ssh zephyr@192.0.2.1
```
