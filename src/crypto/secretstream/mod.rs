//! Stream encryption/file encryption
//!
//! This high-level API encrypts a sequence of messages, or a single message split into an arbitrary
//! number of chunks, using a secret key, with the following properties:
//!
//! * Messages cannot be truncated, removed, reordered, duplicated or modified without this being
//!   detected by the decryption functions.
//! * The same sequence encrypted twice will produce different ciphertexts.
//! * An authentication tag is added to each encrypted message: stream corruption will be detected
//!   early, without having to read the stream until the end.
//! * Each message can include additional data (ex: timestamp, protocol version) in the computation
//!   of the authentication tag.
//! * Messages can have different sizes.
//! * There are no practical limits to the total length of the stream,
//!   or to the total number of individual messages.
//! * Ratcheting: at any point in the stream, it is possible to "forget" the key used to encrypt
//!   the previous messages, and switch to a new key.
//!
//! This API can be used to securely send an ordered sequence of messages to a peer.
//! Since the length of the stream is not limited, it can also be used to encrypt files
//! regardless of their size.
//!
//! It transparently generates nonces and automatically handles key rotation.
//!
//! The `crypto_secretstream_*()` API was introduced in libsodium 1.0.14.
//!
//! # Example (encryption)
//!
//! TODO: Fill in when Rust API stabilizes.
//!
//!
//! # Type safety
//!
//! The `Stream` struct abstracts over the inner state from libsodium, providing
//! type hints.
//!
//! For example, the following code cannot compile, since `Stream<M>` is
//! parameterized by a `StreamMode`. And `push`, `pull` are only implemented for
//! `Stream<Push>` and `Stream<Pull>` respectively.
//!
//! ```compile_fail
//! use sodiumoxide::crypto::secretstream:: oop as secretstream;
//!
//! let key = secretstream::Key::new();
//! let (stream, _header) = secretstream::init_push(&key).unwrap();
//! let _ = stream.pull(&[], None).unwrap();
//! ```
//!
//! Which fails with something like:
//! ``error[E0599]: no method named `pull` found for type `Stream<Push>` in the current scope``

pub mod xchacha20poly1305;

pub use self::xchacha20poly1305::*;
