# walloc

Allocator wrapper that warns under certain error conditions and tries to paper over double-frees.

Usage:

```sh
LD_PRELOAD=/absolute/path/to/walloc.so some_app
```

Compiling for 32-bit (Linux):

```
cargo build --release --target i686-unknown-linux-gnu
```
