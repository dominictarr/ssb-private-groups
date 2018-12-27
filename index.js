function isBox2(ctxt) {
  //we can just do a fairly lax check here, don't check the content
  //is canonical base64, because that check has already been done.
  return 'string' == typeof ctxt && /\.box2$/.test(ctxt)
}

function ctxtToBuffer(ctxt) {
  return isBox2(ctxt) && Buffer.from(ctxt.substring(ctxt.indexOf('.')), 'base64')
}

function idToBuffer (id) {
  return Buffer.from(id.substring(1, id.indexOf('.')), 'base64')
}

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

exports.init = function () {

  var af = AtomicFile(
    path.join(config.path, 'private-groups/local-keys.json')
  )
  var ready = false, waiting = []
  af.get(function (err, data) {
    keyState = data || {msgKeys: [], groupKeys: []}
    ready = true
    while(waiting.length) waiting.shift()()
  })

  //state:
  /*
    {
      <author>: {
        key: <author's latest privacy key>
      }
    }
  */

  var keyState = null
  var state = null
  //cache: {<author>: [scalar_mult(msg_keys[i], <author's latest privacy key>)]
  var cache = {}


  sbot._flumeUse('private-groups/remote-keys', Reduce(1, function (acc, msg) {
    state = acc = acc || {}
    if(msg.content.type === 'private-msg-key') {
      acc[msg.author] = [{sequence: msg.sequence, key: msg.content.key}]
      cache[msg.author] = null
    }
  })

  //sbot._flumeUse('private-groups/old-remote-keys', Level(1, function (data) {
  //  if(msg.content.type === 'private-msg-key') {
  //    return [msg.author, msg.sequence, msg.content.type]
  //  }
  //})

  sbot.addMap(function (data, cb) {
    if(!isBox2(data.value.content)) return cb(null, data)
    //the views and keyState have not been loaded
    //delay processing any box2 messages until they are.
    if(ready) cb(null, data)
    else waiting.push(function () {
      cb(null, data)
    })
  })

  sbot.addUnboxer({
    key:
      function (content, value) {
        if(!isBox2(content)) return
        var a_state = state[value.author]
        if(!a_state) return

        var keys_to_try = cache[value.author]
        if(!keys_to_try) {
          keys_to_try = cache[value.author] = keyState.msgKeys.map(function (key) {
            return scalarmult(a_state.key, curve.private)
          })

        var ctxt = ctxtToBuffer(content), nonce = idToBuffer(value.previous)
        var key = groupbox.unboxKey( //direct recipients
          ctxt, nonce, keys_to_try, 8
        )
        if(key) return key

        var group_keys = []
        for(var id in keyState.groupKeys)
          group_keys.push(getGroupMsgKey(nonce, keyState.groupKeys[id])
        //note: if we only allow groups in the first 4 slots
        //that means better sort them before any individuals
        key = groupbox.unboxKey( //groups we are in
          ctxt, nonce, group_keys, 4
        )
        if(key) return key
      },
    value: function (content, key) {
      if(!isBox2(content)) return
        return groupbox.unboxBody(content, key)
    }
  })

  return {
//    addGroupKey: function (group, cb) {
//      af.get(function () {
//        keyState.groupKeys[hmac(group.id, group.unbox)] = group)
//        af.set(keys, cb)
//      })
//    },
    addCurvePair: function (curve_keys, cb) {
      if(!isCurvePair(curve_keys)) return cb(new Error('expected a pair of curve25519 keys')
      keyState.msgKeys.push(curve_keys)
      cache = {} //clear cache, so it's regenerated up to date.
      //NOTE: identiy adding this key must publish
      //      a message advertising this receive key, or no one
      //      will send them messages!
      af.set(msg_keys, cb)
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







