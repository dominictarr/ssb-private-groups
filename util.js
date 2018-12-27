
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

