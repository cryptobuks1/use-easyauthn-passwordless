const config = {}

config.port = 8084
// 'postgres://<username>:<password>@localhost/<database>'
config.dbConnStr = 'postgres://use_easy_authn_passwordless:password@localhost/use_easy_authn_passwordless'

// EasyAuthn config
// Service Secret Key (SSK)
config.ssk = 'd2ca2f07943551323a7d4c362bef9a7q'

module.exports = config
