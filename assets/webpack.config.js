const path = require("path");
const apiMocker = require('mocker-api');

module.exports = (env, options) => ({
  mode: "development",
  entry: {
    ex_authn: "./js/ex_authn.js",
    app:  "./js/app.js"
  },
  output: {
    filename: "[name].js",
    path: path.join(__dirname, "build")
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader'
        }
      }
    ]
  },
  devServer: {
    contentBase: path.join(__dirname, "build"),
    compress: true,
    port: 4500,
    before: function(app, server, compiler) {
      apiMocker(app, path.resolve('./mocker/index.js'), {});
    }
  }
});
