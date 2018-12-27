var chloride = require('chloride')
var tape = require('tape')
var group_box = require('group-box')
var u = require('../util')
var ssbKeys = require('ssb-keys')
var Scuttlebot = require('ssb-server')
  .use(require('../'))

function hash (s) {
  return chloride.crypto_hash_sha256(Buffer.from(s, 'utf8'))
}

var alice = Scuttlebot({
  temp: true,
  keys: ssbKeys.generate(null, hash('alice_secret1'))
})

var bob = alice.createFeed(ssbKeys.generate(null, hash('bob_secret1')))

function generate (seed) {
  var keys = chloride.crypto_box_seed_keypair(seed)
  return {
    public: keys.publicKey.toString('base64')+'.curve25519',
    private: keys.secretKey.toString('base64')
  }
}

function toBuffer(s) {
  return Buffer.isBuffer(s) ? s : Buffer.from(s, 'base64')
}

function scalarmult (pk,sk) {
  return chloride.crypto_scalarmult(toBuffer(pk), toBuffer(sk))
}
var alice_keys = generate(hash('alice_secret2'))
var bob_keys = generate(hash('bob_secret2'))

tape('create a private-msg-key', function (t) {
  alice.privateGroups.addCurvePair(alice_keys, function (err) {
    if(err) throw err
    alice.publish({
      type: 'private-msg-key',
      key: alice_keys.public
    }, function (err, msg) {
      if(err) throw err

      //bob doesn't call addCurvePair because bob is remote.
      //(we are just adding his feed directly so we don't
      // need to bother with replication)
      bob.publish({
        type: 'private-msg-key',
        key: bob_keys.public
      }, function (err, data) {
        if(err) throw err
        t.ok(data.key)

        var content = { type: 'private', text: 'hello, alice' }
        var ptxt = Buffer.from(JSON.stringify(content))
        var nonce = u.id2Buffer(data.key)
        var keys = [bob_keys, alice_keys].map(function (key) {
          return scalarmult(bob_keys.private, key.public)
        })
        var _key = group_box.unboxKey(ctxt, nonce, keys, 8)
        t.ok(_key, 'message can be decrypted')
        bob.publish(
          ctxt.toString('base64')+'.box2',
          function (err, data) {
            if(err) throw err
            t.ok(data)
            alice.get({id: data.key, private: true}, function (err, msg) {
              if(err) throw err
              t.deepEqual(msg.content, content)
              t.end()

            })
          }
        )
      })
    })
  })
})

tape('cleanup', function (t) {
  alice.close()
  t.end()
})

