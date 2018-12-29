var cl = require('chloride')

//var rx = require('is-canonical-base64')(null, null, 32)
exports.isUnboxKey = function (s) {
  return s === Buffer.from(s, 'base64').toString('base64')
//  return rx.test(s)
}
exports.id2Buffer = function (id) {
  return Buffer.from(id.substring(1, id.indexOf('.')), 'base64')
}

exports.isBox2 = function (ctxt) {
  //we can just do a fairly lax check here, don't check the content
  //is canonical base64, because that check has already been done.
  return 'string' == typeof ctxt && /\.box2$/.test(ctxt)
}

exports.isCurvePair = function (keys) {
  return keys.public && keys.private
}

exports.ctxt2Buffer = function (ctxt) {
  return exports.isBox2(ctxt) && Buffer.from(ctxt.substring(0, ctxt.indexOf('.')), 'base64')
}

function toBuffer(b) {
  return Buffer.isBuffer(b) ? b : Buffer.from(b, 'base64')
}

exports.hmac = function (a, b) {
  return cl.crypto_auth(toBuffer(a), toBuffer(b))
}

exports.getGroupMsgKey = function (previous, group) {
  //or would it be better to use generic hash (with key?)
  return exports.hmac(Buffer.concat([previous, exports.id2Buffer(group.id)]), Buffer.from(group.unbox, 'base64'))
}

exports.scalarmultKeys = function (a_key, recps) {
  return recps.map(function (curve) {
    return cl.crypto_scalarmult(
      toBuffer(curve.private),
      toBuffer(a_key)
    )
  })
}




