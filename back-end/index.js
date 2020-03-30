const config = require('./config')
process.env.NODE_ENV = 'develop'
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const express = require('express')
const app = express()
const http = require('http').Server(app)
const bodyParser = require('body-parser')
const pg = require('pg')
const crypto = require('crypto')
const EasyAuthn = require('easyauthn')

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Content-Type', 'application/json')
  next()
})

http.listen(config.port, 'localhost', () => console.log(`Server running on ${config.port}...`))

app.post('/create', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()
    await db.query('begin')
    const accountResult =
      await db.query(`select * from accounts 
        where username = $1 and created_at < now() - '30 min'::interval
          and is_ready = false for update`, [data.username])
    if (accountResult.rows.length === 0) {
      const insertResult =
        await db.query(`insert into accounts 
          (username, session_id, easyauthn_user_id, login_token, create_token) 
          values ($1, $2, $3, $4, $5) returning *`,
        [data.username,
          crypto.randomBytes(15).toString('hex'),
          crypto.randomBytes(15).toString('hex'),
          crypto.randomBytes(15).toString('hex'),
          crypto.randomBytes(15).toString('hex')])
      if (insertResult.rows.length !== 1) throw new Error()
      out = { status: 'success', createToken: insertResult.rows[0].create_token }
    } else {
      const updateResult =
        await db.query(`update accounts set 
          easyauthn_user_id = $2, 
          login_token = $3, 
          create_token = $4,
          created_at = now()
          where username = $1 and created_at < now() - '30 min'::interval and is_ready = false
          returning *`,
        [data.username,
          crypto.randomBytes(15).toString('hex'),
          crypto.randomBytes(15).toString('hex'),
          crypto.randomBytes(15).toString('hex')])
      if (updateResult.rows.length !== 1) throw new Error()
      out = { status: 'success', createToken: updateResult.rows[0].create_token }
    }
    await db.query('commit')
  } catch (err) {
    console.log(err)
    await db.query('rollback')
    out = { status: 'error', msg: 'Cannot create a user with this username. Try another one!' }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/release-account', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()
    await db.query(`update accounts set created_at = now() - '30 min'::interval 
      where create_token = $1 and is_ready = false`, [data.createToken])
    out = { status: 'success' }
  } catch (err) {
    console.log(err)
    out = { status: 'error' }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/create-account-set-credentials', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()

    const result = await db.query(`select * from accounts 
      where create_token = $1 and is_ready = false and created_at >= now() - '30 min'::interval`, [data.createToken])
    if (result.rows.length !== 1) {
      const notValidCreateTokenError = new Error()
      notValidCreateTokenError.code = 'not-valid-create-token'
      throw notValidCreateTokenError
    }

    const easyAuthn = new EasyAuthn()
    easyAuthn.ssk = config.ssk
    easyAuthn.userId = result.rows[0].easyauthn_user_id
    const easyAuthnResult = await easyAuthn.requestUserRegistration()
    if (easyAuthnResult.status === 200 && easyAuthnResult.data.status === 'ok') {
      out = {
        status: 'success',
        username: result.rows[0].username,
        registrationUrl: easyAuthnResult.data.registrationUrl,
        qrRegistrationUrl: easyAuthnResult.data.qrRegistrationUrl,
        statusRoom: easyAuthnResult.data.statusRoom
      }
    } else {
      console.log(easyAuthnResult)
      throw new Error()
    }
  } catch (err) {
    console.log(err)
    out = { status: 'error', code: err.code }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/create-account-set-credentials-continue', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()

    await db.query('begin')
    const result = await db.query(`select * from accounts 
      where create_token = $1 and is_ready = false and created_at >= now() - '30 min'::interval for update`, [data.createToken])
    if (result.rows.length !== 1) {
      const notValidCreateTokenError = new Error()
      notValidCreateTokenError.code = 'not-valid-create-token'
      throw notValidCreateTokenError
    }

    const easyAuthn = new EasyAuthn()
    easyAuthn.ssk = config.ssk
    easyAuthn.userId = result.rows[0].easyauthn_user_id
    const easyAuthnResult = await easyAuthn.doesUserHaveCredentials()
    if (easyAuthnResult.status === 200 && easyAuthnResult.data.status === 'ok' && easyAuthnResult.data.credentials) {
      await db.query('update accounts set is_ready = true where id = $1', [result.rows[0].id])
      out = { status: 'success', sessionId: result.rows[0].session_id }
    } else {
      console.log(easyAuthnResult)
      throw new Error()
    }
    await db.query('commit')
  } catch (err) {
    console.log(err)
    await db.query('rollback')
    out = { status: 'error', code: err.code }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/sign-in', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()
    const result =
      await db.query(`update accounts
        set login_token = $2
        where username = $1 and is_ready = true 
        returning *`,
      [data.username, crypto.randomBytes(15).toString('hex')])
    if (result.rows.length !== 1) throw new Error()
    out = { status: 'success', loginToken: result.rows[0].login_token }
  } catch (err) {
    out = { status: 'error', msg: 'Wrong username. Try another one!' }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/sign-in-verification', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()
    const result =
      await db.query('select * from accounts where login_token = $1', [data.loginToken])
    if (result.rows.length !== 1) throw new Error()

    const easyAuthn = new EasyAuthn()
    easyAuthn.ssk = config.ssk
    easyAuthn.userId = result.rows[0].easyauthn_user_id
    const easyAuthnResult = await easyAuthn.requestInstanceIdUrl()
    if (easyAuthnResult.status === 200 && easyAuthnResult.data.status === 'ok') {
      out = {
        status: 'success',
        username: result.rows[0].username,
        url: easyAuthnResult.data.url,
        urlQr: easyAuthnResult.data.urlQr,
        instanceId: easyAuthnResult.data.instanceId,
        statusRoom: easyAuthnResult.data.statusRoom
      }
    } else {
      console.log(easyAuthnResult)
      throw new Error()
    }
  } catch (err) {
    out = { status: 'error' }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/sign-in-verification-continue', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()
    const result =
      await db.query('select * from accounts where login_token = $1', [data.loginToken])
    if (result.rows.length !== 1) throw new Error()

    const easyAuthn = new EasyAuthn()
    easyAuthn.ssk = config.ssk
    easyAuthn.userId = result.rows[0].easyauthn_user_id
    easyAuthn.instanceId = data.instanceId
    const easyAuthnResultCredentials = await easyAuthn.isInstanceIdAuthn()
    if (easyAuthnResultCredentials.status === 200 &&
        easyAuthnResultCredentials.data.status === 'ok' &&
        easyAuthnResultCredentials.data.authn === true) {
      out = { status: 'success', sessionId: result.rows[0].session_id }
    } else {
      out = { status: 'error' }
    }
  } catch (err) {
    out = { status: 'error' }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/get-easyauth-creds', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()

    const result = await db.query('select * from accounts where session_id = $1', [data.sessionId])
    if (result.rows.length !== 1) {
      const sessionNotExistError = new Error()
      sessionNotExistError.code = 'session-not-exists'
      throw sessionNotExistError
    }

    const easyAuthn = new EasyAuthn()
    easyAuthn.ssk = config.ssk
    easyAuthn.userId = result.rows[0].easyauthn_user_id
    const easyAuthnResult = await easyAuthn.getUserCredentials()
    if (easyAuthnResult.status === 200 && easyAuthnResult.data.status === 'ok') {
      out = {
        status: 'success',
        username: result.rows[0].username,
        credentials: easyAuthnResult.data.credentials
      }
    } else {
      console.log(easyAuthnResult)
      throw new Error()
    }
  } catch (err) {
    console.log(err)
    out = { status: 'error', code: err.code }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/new-easyauth-creds', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()

    const result = await db.query('select * from accounts where session_id = $1', [data.sessionId])
    if (result.rows.length !== 1) {
      const sessionNotExistError = new Error()
      sessionNotExistError.code = 'session-not-exists'
      throw sessionNotExistError
    }

    const easyAuthn = new EasyAuthn()
    easyAuthn.ssk = config.ssk
    easyAuthn.userId = result.rows[0].easyauthn_user_id
    const easyAuthnResult = await easyAuthn.requestUserRegistration()
    if (easyAuthnResult.status === 200 && easyAuthnResult.data.status === 'ok') {
      out = {
        status: 'success',
        username: result.rows[0].username,
        registrationUrl: easyAuthnResult.data.registrationUrl,
        qrRegistrationUrl: easyAuthnResult.data.qrRegistrationUrl,
        statusRoom: easyAuthnResult.data.statusRoom
      }
    } else {
      console.log(easyAuthnResult)
      throw new Error()
    }
  } catch (err) {
    console.log(err)
    out = { status: 'error', code: err.code }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})

app.post('/delete-easyauth-cred', async (req, res) => {
  let db
  let out
  try {
    const data = JSON.parse(req.body.data)
    db = new pg.Client(config.dbConnStr)
    db.connect()

    const result = await db.query('select * from accounts where session_id = $1', [data.sessionId])
    if (result.rows.length !== 1) {
      const sessionNotExistError = new Error()
      sessionNotExistError.code = 'session-not-exists'
      throw sessionNotExistError
    }

    const easyAuthn = new EasyAuthn()
    easyAuthn.ssk = config.ssk
    easyAuthn.userId = result.rows[0].easyauthn_user_id
    easyAuthn.credentialId = data.credId
    easyAuthn.keepAtLeastOne = true
    const easyAuthnResult = await easyAuthn.deleteUserCredential()
    if (easyAuthnResult.status === 200 && easyAuthnResult.data.status === 'ok') {
      out = { status: 'success' }
    } else {
      console.log(easyAuthnResult)
      throw new Error()
    }
  } catch (err) {
    console.log(err)
    out = { status: 'error', code: err.code }
  } finally {
    if (db) await db.end()
  }
  return res.send(out)
})
