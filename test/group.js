var chloride   = require('chloride')
var crypto     = require('crypto')
var tape       = require('tape')
var group_box  = require('group-box')
var u          = require('../util')
var ssbKeys    = require('ssb-keys')

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

var alice_prev, bob_prev

tape('first message cannot be encrypted', function (t) {
  alice.privateGroups.addCurvePair(alice_keys, function (err) {
    if(err) throw err
    alice.publish({
      type: 'private-msg-key',
      key: alice_keys.public
    }, function (err, data) {
      if(err) throw err
      alice_prev = data.key
      bob.publish({
        type: 'private-msg-key',
        key: bob_keys.public
      }, function (err, data) {
        bob_prev = data.key
        if(err) throw err
        t.end()
      })
    })
  })
})

function encrypt (content, prev, keys) {
  return group_box.box(
    Buffer.from(JSON.stringify(content), 'utf8'),
    Buffer.isBuffer(prev) ? prev : u.id2Buffer(prev),
    keys
  ).toString('base64')+'.box2'
}

tape('bob creates a group', function (t) {
  var content = {
    type: 'event',
    text: "alice's surprise birthday"
  }
  //hot wiring group_box here!
  //todo: make group-box fully deterministic, so payload_key
  //may be passed in.
  var en_key = crypto.randomBytes(32)
  var ctxt = encrypt(content, bob_prev, [en_key])
  var nonce = u.id2Buffer(bob_prev)
  var group_key = group_box.unboxKey(u.ctxt2Buffer(ctxt), nonce, [en_key], 8)

  t.notEqual(group_key, en_key)
  t.ok(group_key, 'message can be decrypted')

  //create a group
  bob.publish(
    ctxt,
    function (err, data) {
      if(err) throw err
      t.ok(data.key)
      var group_id = data.key
      nonce = u.id2Buffer(data.key)
      var theme = {
        type:'post', text: 'Theme: dress up as your favorite TLA'
      }
      //a message for the group
      bob.publish(encrypt(theme, data.key, [
        u.hmac(Buffer.concat([nonce, u.id2Buffer(group_id)]), group_key)
      ]), function (err, data) {
        if(err) throw err
        var msg_in_group = data.key

        var group_msg_key = u.hmac(Buffer.concat([nonce, u.id2Buffer(group_id)]), group_key)
        var keys = [bob_keys, alice_keys].map(function (key) {
          return scalarmult(bob_keys.private, key.public)
        })

        //message inviting alice to the group
        bob.publish(
          encrypt({
            type: 'entrust',
            group: group_id,
            unbox: group_key.toString('base64')
          }, data.key, keys.concat([group_msg_key])),
          function (err, data) {
            if(err) throw err
            var invite_id = data.key
            t.ok(data)
            alice.get({id: invite_id, private: true}, function (err, msg) {
              if(err) throw err
              t.equal(msg.content.group, group_id)
              t.equal(msg.content.unbox, group_key.toString('base64'))
              alice.privateGroups.addGroupKey({
                id: msg.content.group,
                unbox: msg.content.unbox
              }, function (err) {
                if(err) throw err
                alice.get({private: true, id: msg_in_group}, function (err, msg) {
                  if(err) throw err
                  t.deepEqual(msg.content, theme)
                  t.end()
                })
              })
            })
          }
        )
      })
    }
  )
})

tape('cleanup', function (t) {
  alice.close()
  t.end()
})

