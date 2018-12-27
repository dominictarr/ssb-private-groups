var chloride = require('chloride')
var tape = require('tape')
var group_box = require('group-box')
var u = require('../util')
var Scuttlebot = require('ssb-server')
  .use(require('../'))

var alice = Scuttlebot({
  temp: true
})

var bob = alice.createFeed()

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
function hash (s) {
  return chloride.crypto_hash_sha256(Buffer.from(s, 'utf8'))
}
var alice_keys = generate(hash('alice_secret'))
var bob_keys = generate(hash('bob_secret'))

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
        console.log(data)
        t.ok(data.key)

        var content = { type: 'private', text: 'hello, alice' }
        var ptxt = Buffer.from(JSON.stringify(content))
        var nonce = u.id2Buffer(data.key)
        var keys = [bob_keys, alice_keys].map(function (key) {
          return scalarmult(bob_keys.private, key.public)
        })
        var keys2 = [bob_keys].map(function (key) {
          return scalarmult(alice_keys.private, key.public)
        })
        console.log('plaintext.length', ptxt.length)

        var ctxt = group_box.box(
          ptxt,
          nonce,
          keys
        )
//        console.log("CTXT", ctxt.toString('base64'))
//        console.log("NONCE", nonce)
//        console.log("KEYS", keys)
//        console.log("KEYS2", keys2)
        var _key = group_box.unboxKey(ctxt, nonce, keys, 8)
        console.log("INPUT", {
          ctxt: ctxt.toString('hex'),
          nonce: nonce,
          key: _key
        })
        console.log(
          'INPUT_TEST',
          chloride.crypto_hash_sha256(Buffer.concat([ctxt, nonce, _key])),
group_box.unboxBody(ctxt, nonce, _key).toString()
        )
        console.log('d.ptxt', group_box.unboxBody(ctxt, nonce, _key).toString())

//        console.log('ctxt.length', ctxt.length)
        bob.publish(
          ctxt.toString('base64')+'.box2',
          function (err, data) {
            if(err) throw err
            t.ok(data)
//            console.log(data)
//            alice.privateGroups.get(function () {
              alice.get({id: data.key, private: true}, function (err, msg) {
                if(err) throw err
                t.deepEqual(msg.content, content)
                t.end()

              })
  //          })
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




