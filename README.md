# ssb-private-groups


## receive key

to indicate you support box2, post a message

```
{
  type: 'private-msg-key',
  key: curve25519.public
}
``
when decrypting messages from another feed,
you know it came from their most recent
private message key, because they are in a strict order.

when decrypting messages _for your feed_ these must
be combined with each private-msg-key you retain.
when rotating keys, it is advisable to keep both keys
alive for an overlap period, to improve chances that
sender has your new key when they write a message to you.

If they write a message to a key you have discarded,
you won't know, because you'll be unable to decrypt that message.



## License

MIT
