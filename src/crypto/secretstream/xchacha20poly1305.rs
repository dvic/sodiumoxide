//! `crypto_secretstream_xchacha20poly1305`
use ffi::{
    crypto_secretstream_xchacha20poly1305_ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_PUSH,
    crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_messagebytes_max,
    crypto_secretstream_xchacha20poly1305_pull, crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_rekey, crypto_secretstream_xchacha20poly1305_state,
};
use libc::c_ulonglong;
#[cfg(not(feature = "std"))]
use prelude::*;
use randombytes::randombytes_into;
use std::default::Default;
use std::marker::PhantomData;
use std::mem;
use std::ops::Drop;
use std::ptr;

/// Returns the maximum length of an individual message.
// TODO: use `const fn` when stable
// (https://github.com/rust-lang/rust/issues/24111).
pub fn messagebytes_max() -> usize {
    unsafe { crypto_secretstream_xchacha20poly1305_messagebytes_max() }
}

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;

/// Number of bytes in a `Header`.
/// An encrypted stream starts with a short header, whose size is HEADERBYTES
/// bytes. That header must be sent/stored before the sequence of encrypted
/// messages, as it is required to decrypt the stream.
pub const HEADERBYTES: usize = crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;

/// Number of added bytes. The ciphertext length is guaranteed to always be
/// message length + ABYTES.
pub const ABYTES: usize = crypto_secretstream_xchacha20poly1305_ABYTES as usize;

/// Tag message: the most common tag, that doesn't add any information about the
/// nature of the message.
const TAG_MESSAGE: u8 = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8;

/// Tag push: indicates that the message marks the end of a set of messages, but
/// not the end of the stream.
/// For example, a huge JSON string sent as multiple chunks can use this tag to
/// indicate to the application that the string is complete and that it can be
/// decoded. But the stream itself is not closed, and more data may follow.
const TAG_PUSH: u8 = crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8;

/// Tag rekey: "forget" the key used to encrypt this message and the previous
/// ones, and derive a new secret key.
const TAG_REKEY: u8 = crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8;

/// Tag final: indicates that the message marks the end of the stream and erases
/// the secret key used to encrypt the previous sequence.
const TAG_FINAL: u8 = crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8;

/// A tag is encrypted and attached to each message before the authentication
/// code is generated over all data. A typical encrypted stream simply attaches
/// `0` as a tag to all messages, except the last one which is tagged as
/// `Tag::Final`. When decrypting the tag is retrieved and may be used.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tag {
    /// Message, the most common tag, that doesn't add any information about the
    /// nature of the message.
    Message = TAG_MESSAGE,
    /// Push: indicates that the message marks the end of a set of messages, but
    /// not the end of the stream.
    /// For example, a huge JSON string sent as multiple chunks can use this tag
    /// to indicate to the application that the string is complete and that it
    /// can be decoded. But the stream itself is not closed, and more data may
    /// follow.
    Push = TAG_PUSH,
    /// Rekey: "forget" the key used to encrypt this message and the previous
    /// ones, and derive a new secret key.
    Rekey = TAG_REKEY,
    /// Final: indicates that the message marks the end of the stream and erases
    /// the secret key used to encrypt the previous sequence.
    Final = TAG_FINAL,
}

impl Default for Tag {
    fn default() -> Self {
        Tag::Message
    }
}

impl Tag {
    /// Returns the corresponding `Tag` given a `u8`, else `Err(())`.
    fn from_u8(tag: u8) -> Result<Tag, ()> {
        match tag {
            TAG_MESSAGE => Ok(Tag::Message),
            TAG_PUSH => Ok(Tag::Push),
            TAG_REKEY => Ok(Tag::Rekey),
            TAG_FINAL => Ok(Tag::Final),
            _ => Err(()),
        }
    }
}

new_type! {
    /// `Key` for symmetric authenticated encryption.
    ///
    /// When a `Key` goes out of scope its contents will be overwritten in
    /// memory.
    secret Key(KEYBYTES);
}

/// `gen_key()` randomly generates a secret key
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_key() -> Key {
    let mut key = [0; KEYBYTES];
    randombytes_into(&mut key);
    Key(key)
}

new_type! {
    /// An encrypted stream starts with a short header, whose size is HEADERBYTES bytes.
    /// That header must be sent/stored before the sequence of encrypted messages,
    /// as it is required to decrypt the stream.
    public Header(HEADERBYTES);
}

/// `Stream` contains the state for multi-part (streaming) computations. This
/// allows the caller to process encryption of a sequence of multiple messages.
pub struct Stream<M: StreamMode> {
    state: crypto_secretstream_xchacha20poly1305_state,
    finalized: bool,
    marker: PhantomData<M>,
}

impl<M: StreamMode> Stream<M> {
    /// Explicit rekeying. This updates the internal state of the `Stream<Pull>`,
    /// and should only be called in a synchronized manner with how the
    /// corresponding `Stream` called it when encrypting the stream. Returns
    /// `Err(())` if the stream was already finalized, else `Ok(())`.
    pub fn rekey(&mut self) -> Result<(), ()> {
        if self.finalized {
            return Err(());
        }
        unsafe {
            crypto_secretstream_xchacha20poly1305_rekey(&mut self.state);
        }
        Ok(())
    }

    /// Returns true if the stream is finalized.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }
}

impl Stream<Push> {
    /// Initializes an `Stream` using a provided `key`. Returns the
    /// `Stream` object and a `Header`, which is needed by the recipient to
    /// initialize a corresponding `Stream<Pull>`. The `key` will not be needed be
    /// required for any subsequent authenticated encryption operations.
    /// If you would like to securely generate a key and initialize an
    /// `Stream` at the same time see the `new` method.
    /// Network protocols can leverage the key exchange API in order to get a
    /// shared key that can be used to encrypt streams. Similarly, file
    /// encryption applications can use the password hashing API to get a key
    /// that can be used with the functions below.
    pub fn init_push(key: &Key) -> Result<(Stream<Push>, Header), ()> {
        let mut header: [u8; HEADERBYTES] = unsafe { mem::uninitialized() };
        let mut state: crypto_secretstream_xchacha20poly1305_state =
            unsafe { mem::uninitialized() };
        let rc = unsafe {
            crypto_secretstream_xchacha20poly1305_init_push(
                &mut state,
                header.as_mut_ptr(),
                key.0.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(());
        }
        Ok((
            Stream::<Push> {
                state,
                finalized: false,
                marker: PhantomData,
            },
            Header(header),
        ))
    }

    /// All data (including optional fields) is authenticated. Encrypts a
    /// message `m` and its `tag`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    pub fn push(&mut self, m: &[u8], ad: Option<&[u8]>, tag: Tag) -> Result<Vec<u8>, ()> {
        if self.finalized {
            return Err(());
        }
        let m_len = m.len();
        if m_len > messagebytes_max() {
            return Err(());
        }
        if tag == Tag::Final {
            self.finalized = true;
        }

        let (ad_p, ad_len) = ad
            .map(|ad| (ad.as_ptr(), ad.len()))
            .unwrap_or((ptr::null(), 0));

        let buf_len = m_len + ABYTES;
        let mut buf = Vec::with_capacity(buf_len);
        let rc = unsafe {
            buf.set_len(buf_len);
            crypto_secretstream_xchacha20poly1305_push(
                &mut self.state,
                buf.as_mut_ptr(),
                &mut (buf_len as c_ulonglong),
                m.as_ptr(),
                m_len as c_ulonglong,
                ad_p,
                ad_len as c_ulonglong,
                tag as u8,
            )
        };
        if rc != 0 {
            return Err(());
        }
        Ok(buf)
    }

    /// Create a ciphertext for an empty message with the `TAG_FINAL` added
    /// to signal the end of the stream. Since the `Stream` is not usable
    /// after this point, this method consumes the `Stream.
    pub fn finalize(mut self, ad: Option<&[u8]>) -> Result<Vec<u8>, ()> {
        self.push(&[], ad, Tag::Final)
    }
}

impl Stream<Pull> {
    /// Initializes a `Stream<Pull>` given a secret `Key` and a `Header`. The key
    /// will not be required any more for subsequent operations. `Err(())` is
    /// returned if the header is invalid.
    pub fn init_pull(header: &Header, key: &Key) -> Result<Stream<Pull>, ()> {
        let mut state: crypto_secretstream_xchacha20poly1305_state =
            unsafe { mem::uninitialized() };
        let rc = unsafe {
            crypto_secretstream_xchacha20poly1305_init_pull(
                &mut state,
                header.0.as_ptr(),
                key.0.as_ptr(),
            )
        };
        if rc == -1 {
            // NOTE: this return code explicitly means the header is invalid,
            // but when implementing error types we should still consider the
            // possibility of some other non-zero code below with a generic call
            // to external function failed error.
            return Err(());
        } else if rc != 0 {
            return Err(());
        }
        Ok(Stream::<Pull> {
            state: state,
            finalized: false,
            marker: PhantomData,
        })
    }

    /// Pull an encrypted message from the stream, verify and decrypt it.
    ///
    /// Additionally returns the tag.
    pub fn pull(&mut self, c: &[u8], ad: Option<&[u8]>) -> Result<(Vec<u8>, Tag), ()> {
        if self.finalized {
            return Err(());
        }
        let c_len = c.len();
        if c_len < ABYTES {
            // An empty message will still be at least ABYTES.
            return Err(());
        }
        let m_len = c_len - ABYTES;
        if m_len > messagebytes_max() {
            return Err(());
        }
        let (ad_p, ad_len) = ad
            .map(|ad| (ad.as_ptr(), ad.len()))
            .unwrap_or((ptr::null(), 0));
        let mut tag: u8 = unsafe { mem::uninitialized() };
        let mut buf = Vec::with_capacity(m_len);
        let rc = unsafe {
            buf.set_len(m_len);
            crypto_secretstream_xchacha20poly1305_pull(
                &mut self.state,
                buf.as_mut_ptr(),
                &mut (m_len as c_ulonglong),
                &mut tag,
                c.as_ptr(),
                c_len as c_ulonglong,
                ad_p,
                ad_len as c_ulonglong,
            )
        };
        if rc != 0 {
            return Err(());
        }
        let tag = Tag::from_u8(tag)?;
        Ok((buf, tag))
    }
}

// As additional precaution, rotate the keys when dropping the `Stream`
// to ensure keys do no stay in memory.
impl<T: StreamMode> Drop for Stream<T> {
    fn drop(&mut self) {
        let _ = self.rekey();
    }
}

/// The trait that distinguishes between the pull and push modes of a Stream.
pub trait StreamMode: private::Sealed {}

/// Represents the push mode of a Stream.
pub enum Push {}

/// Represents the pull mode of a Stream.
pub enum Pull {}

mod private {
    pub trait Sealed {}

    impl Sealed for super::Push {}
    impl Sealed for super::Pull {}
}

impl StreamMode for Push {}
impl StreamMode for Pull {}

#[cfg(test)]
mod test {
    use super::*;
    use randombytes::randombytes_into;

    #[test]
    fn test_push_pull() {
        let mut msg1 = [0; 128];
        let mut msg2 = [0; 34];
        let mut msg3 = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);

        let key = gen_key();
        let (mut state, header) = Stream::init_push(&key).unwrap();
        let c1 = state.push(&msg1, None, Tag::Message).unwrap();
        assert!(!state.is_finalized());
        let c2 = state.push(&msg2, None, Tag::Push).unwrap();
        assert!(!state.is_finalized());
        let c3 = state.push(&msg3, None, Tag::Final).unwrap();
        assert!(state.is_finalized());

        let mut state = Stream::init_pull(&header, &key).unwrap();

        let (m1, t1) = state.pull(&c1, None).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);

        let (m2, t2) = state.pull(&c2, None).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);

        let (m3, t3) = state.pull(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
    }
}
