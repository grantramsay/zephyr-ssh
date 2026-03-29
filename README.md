# Zephyr SSH

An SSH client/server for Zephyr RTOS.

This is an experimental project. I recommend only running this inside a trusted
network. Consider adding a dummy user when interacting with your computer:
```shell
# Create a new user
sudo useradd -m test-user
sudo passwd test-user
# Generate host key
sudo -H -u test-user bash -c 'ssh-keygen -t rsa -b 2048 -N "" -f ~/.ssh/id_rsa'
```

## Sample

A sample that allows connecting to your host machine from Zephyr SHH client, or
connecting to Zephyr SSH server from your host machine. Supports password or
public key authentication, host key generation/storage/export and authorized
keys import/storage.

[Sample README](samples/net/ssh/README.md)

![](demo.gif)

## Supported

* Multiple SSH Servers
* Multiple client connections per server
* Multiple SSH Clients
* Multiple channels per connection
* Password authentication
* Public key authentication
* RSA host key generation
* Automatic key re-exchange
* Channel flow control
* Clients/server shell
* Supported algorithms:
  * Key exchange (kex)
    * curve25519-sha256
  * Host key:
    * rsa-sha2-256
    * rsa-sha2-512
  * Encryption
    * aes128-ctr
  * Message authentication code (mac)
    * aes128-ctr
  * Compression
    * none

## TODO

* Large tidy up / refactor
* Documentation and code comments
* Coding style (run checkpatch)
* Tidy error codes (currently a mishmash or errno and -1)
* Unit tests
  * These are difficult to write with encryption enabled
    (fake Mbed-TLS functions could be useful)
* Test on real hardware (currently only tested on native_sim board)
* Convert to PSA crypto
* Support additional kex/host-key/encryption/mac algorithms
* Generic interfaces for different kex/host-key/encryption/mac algorithms
* Forward/reverse port forwarding
* Idle timeout / first auth timeout
* "First kex packet follows" support
* Misc hardening (zeroize secrets etc)
* Keystroke timing mitigation
* "Strict kex" (terrapin attack)
* IPv6
* DNS
* Everything else I've forgotten or overlooked

## Usage

TODO

## Implementation details

### Memory usage

To conform to RFC4253 the implementation must be able to process packets
up to 35,000 bytes in length. However in practice you may get away with
far less.

* Static server/client instances
  * Avoids dynamic allocation while encapsulating implementation details
* Static TX/RX buffer per transport
  * The SSH specification requires these buffers to be ~35,000 bytes.
    In practice, you might get away with much less (~4kB each?)
* Private heap per transport for kex/algs related items
* Message queue for interacting with server/client instances locally
* Four (small-ish) ring buffers per channel (stdio/stderr in and out)

Note: Mbed-TLS allocates memory from a global heap.

TODO: Show actual ROM/RAM memory usage on a Cortex-M device.

### Thread usage

Each SSH server/client uses a single thread. This means there is a slight
coupling between multiple client connections to a single server.
Server/client threads poll on socket input data and are woken/interrupted by an
eventfd. There is no polling on output data, send blocks until completed (`sendall`).

Note: Each SSH server shell channel requires an additional thread.

### String handling

The SSH protocol passes strings as `[length][value]` (similar to Pascal strings)
rather than NULL terminated C strings. The internal implementation uses the SSH
string representation to avoid copying strings into fixed size buffers.
