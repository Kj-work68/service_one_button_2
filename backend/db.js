const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'password@1234',
  database: 'service_1'
});

const promisePool = pool.promise();

module.exports = promisePool;
