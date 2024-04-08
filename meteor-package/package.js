Package.describe({
  name: "minhna:accounts-2fa-ext",
  version: "0.0.1",
  // Brief, one-line summary of the package.
  summary: "Extended version of accounts-2fa",
  // URL to the Git repository containing the source code for this package.
  git: "https://github.com/minhna/meteor-accounts-2fa-ext.git",
  documentation: "README.md",
});

Package.onUse(function (api) {
  api.use(["accounts-2fa"], ["client", "server"]);
  api.use("ecmascript");
  api.use("typescript@4.0.0 || 5.0.0 || 6.0.0");

  api.addFiles(["server.ts"], "server");
  api.addFiles(["client.ts"], "client");
});

Package.onTest(function (api) {
  api.use("accounts-2fa");
  api.use("ecmascript");
  api.use("tinytest");
  api.use("minhna:accounts-2fa-ext");

  api.mainModule("server-tests.ts", "server");
  api.mainModule("client-tests.ts", "client");
});
