const config = require('./config')
const connect = require('connect')
const serveStatic = require('serve-static')
const path = require('path')

connect()
  .use(serveStatic(path.join(__dirname, 'www')))
  .listen(config.port, 'localhost', () => console.log(`Server running on ${config.port}...`))
