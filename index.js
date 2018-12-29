var AtomicFile = require('atomic-file')
var path       = require('path')
var Reduce     = require('flumeview-reduce')
var group_box  = require('group-box')
var mkdirp     = require('mkdirp')
var u          = require('./util')
var cl         = require('chloride')

//by deriving the message key from the group id (the founding
//message id) and the unbox key for that message, this ensures
//someone can't decrypt the message without knowing the founding
//message, therefore avoiding surruptious sharing the group.
//they can't _not_ know who made the group, so if someone else
//shares it to them, they know they are being sneaky.

//and, you can verify this property from the design! you can't
//rewrite this code so they don't know the founding message
//and still be able to decrypt these messages.

function getGroupMsgKey(previous, group) {
  return hmac(Buffer.concat([previous, group.id]), group.unbox)
}

exports.name = 'private-groups'

exports.init = function (sbot, config) {

  var dir = path.join(config.path, 'private-groups')

  var af = AtomicFile(path.join(dir, 'local-keys.json'))
  var ready = false, waiting = []
  mkdirp(dir, function () {
    af.get(function (err, data) {
      keyState = data || {msgKeys: [], groupKeys: []}
      ready = true
      while(waiting.length) waiting.shift()()
    })
  })

  function onReady (fn) {
    if(ready) fn()
    else waiting.push(fn)
  }

  //state:
  /*
    {
      <author>: [{
        sequence: <sequence at which author set this key>,
        key: <author's latest privacy key>
      }]
    }
  */

  var keyState = null
  var state = null
  //cache: {<author>: [scalar_mult(msg_keys[i], <author's latest privacy key>)]
  var cache = {}

  //maybe in the future, use a level db here.
  var remoteKeys = sbot._flumeUse('private-groups/remote-keys', Reduce(1, function (acc, data) {
    state = acc = acc || {}
    var msg = data.value
    if(msg.content.type === 'private-msg-key') {
      acc[msg.author] = [{sequence: msg.sequence, key: msg.content.key}]
      cache[msg.author] = null
    }
    return acc
  }))

  sbot.addMap(function (data, cb) {
    if(!u.isBox2(data.value.content)) return cb(null, data)
    //the views and keyState have not been loaded
    //delay processing any box2 messages until they are.
    if(ready) cb(null, data)
    else waiting.push(function () {
      cb(null, data)
    })
  })

  sbot.addUnboxer({
    name: 'private-msg-key',
    key: function (content, value) {
      if(!u.isBox2(content)) return
      //a_state is reverse chrono list of author's private-msg-keys
      //take the latest key that has sequence less than message
      //to decrypt
      var a_state = state[value.author]
      if(!a_state) return console.log('no author state')

      var keys_to_try = cache[value.author]
      var a_key
      for(var i = 0; i < a_state.length; i++) {
        if(a_state[i].sequence < value.sequence) {
          a_key = a_state[i].key
          break;
        }
      }
      if(!a_key) return console.log('no author key')

      if(!keys_to_try)
        keys_to_try = cache[value.author] = keyState.msgKeys.map(function (curve) {
          return cl.crypto_scalarmult(
            Buffer.from(curve.private, 'base64'),
            Buffer.from(a_key, 'base64')
          )
        })

      //the very first message cannot be a group_box.
      if(value.previous == null) return
      var ctxt = u.ctxt2Buffer(content)
      var nonce = u.id2Buffer(value.previous)

      var key = group_box.unboxKey(ctxt, nonce, keys_to_try, 8)
      if(key) return key

      //should group keys be included in this plugin?
      //yes, because box2 supports both direct keys and group keys.
      var group_keys = []
      for(var id in keyState.groupKeys)
        group_keys.push(getGroupMsgKey(nonce, keyState.groupKeys[id]))

      //note: if we only allow groups in the first 4 slots
      //that means better sort them before any individuals
      key = group_box.unboxKey( //groups we are in
        ctxt, nonce, group_keys, 4
      )
      if(key) return key

    },
    value: function (content, key, value) {
      if(!u.isBox2(content)) return
      var ctxt = u.ctxt2Buffer(content)
      var nonce = u.id2Buffer(value.previous)
      try {
        return JSON.parse(group_box.unboxBody(ctxt, nonce, key).toString())
      } catch (_) {}
    }
  })

  return {
    get: remoteKeys.get,
    addGroupKey: function (group, cb) {
      af.get(function () {
        keyState.groupKeys[hmac(group.id, group.unbox)] = group)
        af.set(keys, cb)
      })
    },
    addCurvePair: function (curve_keys, cb) {
      onReady(function () {
        if(!u.isCurvePair(curve_keys))
          return cb(new Error('expected a pair of curve25519 keys'))
        keyState.msgKeys.push(curve_keys)
        cache = {} //clear cache, so it's regenerated up to date.
        //NOTE: identiy adding this key must publish
        //      a message advertising this receive key, or no one
        //      will send them messages!
        af.set(keyState, cb)
      })
    },
//forgetting old keys. crude basis for forward secrecy.
//you will no longer be able to decrypt messages sent to curve_pk
    forget: function (curve_pk, cb) {
      af.get(function () {
        for(var i = msg_keys.length-1; i >= 0; i--)
          if(curve_pk == msg_keys[i].public)
            msg_keys.splice(i, 1)
        cache = {} //clear cache, will be regenerated.
        af.set(msg_keys, cb)
      })
    }
  }
}

