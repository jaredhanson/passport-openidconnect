

var log_to_console = function (message) {
  console.log(message);
};

var no_op = function () {};

module.exports = (process.env.NODE_ENV !== 'production' || process.env.DEBUG) ? log_to_console : no_op;