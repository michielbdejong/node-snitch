//This lets you run a shared-hosting server which registers missing certificates
// on the fly, while continuing to host the other domains on the same IP address.
//It will save all certificates under /etc/letsencrypt on that server, and use
//them from there for the rest of the deployed server's lifetime.

var fs = require('fs'),
    mkdirp = require('mkdirp'),
    acme = require('node-letsencrypt'),
    crypto = require('crypto');

var acmeServer = 'www.letsencrypt-demo.org';

var DEFAULT_KEY =
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  "MIIBOwIBAAJBAI0wy6Yxr8oK4IVCt7Ma+0rFDUJqA0xeDxrJ6xg8wVfaQydnNXLH\n" +
  "kcBeriMhC37DUygRigkEea5RSQkJcE521s8CAwEAAQJAcfjsu6iqNZdYLFpx/YOP\n" +
  "TIkKrgzzwqa+3KoYO8V3cVlNEZbzSFn0CAnznLPYzAY7yibDAVYWLVgJsdldOvtQ\n" +
  "UQIhAMH/JrN5znZigVnqxFrHJGbNjBTnir9CG1YYZsXWrIjJAiEAulEKSqpnuv9C\n" +
  "5btfRZ2E0oVal6+XzOajNagMqPJhRtcCIQCui7nwhcnj7mFf28Frw/3WmV5OeL33\n" +
  "s60Q28esfaijMQIgOjwCP3wrl+MZAb0i9htZ3IMZ4bdcdwrPkIHKEzRO+1kCIQC/\n" +
  "jUlCS7ny/4g4tY5dngWhQk3NUJasFzNuzTSx4ZGYWw==\n" +
  "-----END RSA PRIVATE KEY-----\n";

var DEFAULT_CERT =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBWDCCAQKgAwIBAgIBATANBgkqhkiG9w0BAQUFADAcMRowGAYDVQQDExFhbm9u\n" +
  "eW1vdXMuaW52YWxpZDAeFw0xNDA5MTMxOTU1MjRaFw0xNTA5MTMxOTU1MjRaMBwx\n" +
  "GjAYBgNVBAMTEWFub255bW91cy5pbnZhbGlkMFwwDQYJKoZIhvcNAQEBBQADSwAw\n" +
  "SAJBAI0wy6Yxr8oK4IVCt7Ma+0rFDUJqA0xeDxrJ6xg8wVfaQydnNXLHkcBeriMh\n" +
  "C37DUygRigkEea5RSQkJcE521s8CAwEAAaMvMC0wCQYDVR0TBAIwADALBgNVHQ8E\n" +
  "BAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEFBQADQQBpHaM7\n" +
  "mwRj19nt7sGb/trlxu5Ra0Ic4RGLI/VOZGWVV6hb2G559J2WdrdMS98U3L95lOoX\n" +
  "2fhD1yUCrh3aNtZP\n" +
  "-----END CERTIFICATE-----\n";

function getHttpsOptionsFromDisk(certificatesFolder, domain, callback) {
  fs.readFile(certificatesFolder + domain + '/cert.pem', function(err1, certData) {
    if (err1) {
      callback(err1);
    } else {
      fs.readFile(certificatesFolder + domain + '/key.pem', function(err2, keyData) {
        if (err2) {
          callback(err2);
        } else {
          fs.readFile(certificatesFolder + domain + '/ca.pem', function(err3, caData) {
            if (err3) {
              callback(null, {
                key: keyData,
                cert: certData
              });
            } else {
              callback(null, {
                key: keyData,
                cert: certData,
                ca: caData
              });
            }
          });
        }
      });
    }
  });
}

function saveHttpsOptionsToDisk(certificatesFolder, domain, options, callback) {
  mkdirp(certificatesFolder + domain, function(err1) {
    if (err1) {
      callback(err1);
    } else {
      fs.writeFile(certificatesFolder + domain + '/key.pem', options.key, function (err2) {
        if (err2) {
          callback(err2);
        } else {
          fs.writeFile(certificatesFolder + domain + '/cert.pem', options.cert, function (err3) {
            callback(err3);
          });
        }
      });
    }
  });
}

function acmeHardResultToHttpsOptions(subjectKeyPair, result) {
  return {
    key: acme.privateKeyToPem(subjectKeyPair.privateKey),
    cert: acme.certificateToPem(result.certificate.toString('base64').replace(/[+]/g, "-").replace(/\//g, "_").replace(/=/g,""))
  };
}

Store.prototype.loadContexts = function() {
  var self = this;
  fs.readdir(this.certificatesFolder, function(err, listing) {
    if (err) {
      self.errorCallback('no certificates folder found at '+self.certificatesFolder);
      return;
    }
    console.log(listing);
    for (var i=0; i<listing.length; i++) {
      getHttpsOptionsFromDisk(self.certificatesFolder, listing[i], (function(domain) {
        return function(err, options) {
          if (err) {
            self.errorCallback(err);
          } else {
            console.log('adding certificate for ' + domain);
            self.contexts[domain] = crypto.createCredentials(options).context;
          }
        };
      })(listing[i]));
    }
  });
}

function registerCert(servername, callback) {
  var tokens = {};
  var keySize = 2048;
  var acmeServer = 'www.letsencrypt-demo.org';
  var authzURL = "https://" + acmeServer + "/acme/new-authz";
  var certURL = "https://" + acmeServer + "/acme/new-cert";
  console.log('getting cert for '+servername);
  var client = acme.createClient(authzURL, certURL, function(domain, challenge, response, challengeType) {
    console.log('challenge callback called', domain, challenge.path, response.token, challengeType);
    if (servername === domain) {
      tokens[challenge.path] = response.token;
    }
  });
  var authorizedKeyPair = client.generateKeyPair(keySize);
  var subjectKeyPair = client.generateKeyPair(keySize);
  client.authorizeKeyPair(authorizedKeyPair, servername, function(result) {
    // Result has a recovery key
    if (result.error) {
      callback(result.error);
    } else {
      client.issueCertificate(authorizedKeyPair, subjectKeyPair,
                              servername, function(result) {
        // Result has certificate
        if (result.error) {
          callback(result.error);
        } else {
          callback(null, acmeHardResultToHttpsOptions(subjectKeyPair, result));
        }
      });
    }
  });
  return function(challenge) {
    console.log('got challenge '+challenge+' for '+servername, tokens);
    return tokens[challenge];
  };
}

module.exports.DEFAULT_KEY = DEFAULT_KEY;
module.exports.DEFAULT_CERT = DEFAULT_CERT;
module.exports.Store = Store;

function Store(setCertificatesFolder, setLoadInterval, setErrorCallback, setWhitelistCallback) {
  this.certificatesFolder = setCertificatesFolder;
  if (this.certificatesFolder.substr(-1) !== '/') {
    this.certificatesFolder += '/';
  }
  this.loadTimer = setInterval(this.loadContexts.bind(this), setLoadInterval);
  this.contexts = {};
  this.pendingCerts = {};
  this.errorCallback = setErrorCallback;
  this.whitelist = setWhitelistCallback;
  this.loadContexts();
  this.defaultContext = crypto.createCredentials({
    key: DEFAULT_KEY,
    cert: DEFAULT_CERT
  }).context;
}

Store.prototype.getContext = function(servername) {
  if (this.contexts[servername]) {
    console.log('SNI hit for ' + servername);
    return this.contexts[servername];
  } else {
    console.log('SNI miss for ' + servername);
    if (servername.substr(-('.acme.invalid'.length)) === '.acme.invalid') {
      console.log('Ignoring');
    } else if (this.pendingCerts[servername]) {
      console.log('Registration already pending');
    } else if (this.whitelist(servername)) {
      console.log('Registering...');
      this.pendingCerts[servername] = registerCert(servername, function(err, options) {
        if (err) {
          console.log('could not obtain cert', servername, err);
        } else {
          console.log('obtained cert', servername, options);
          saveHttpsOptionsToDisk(servername, options, function(err2) {
            console.log('saved cert to disk', servername, err2);
          });
          this.contexts[servername] = crypto.createCredentials(options).context;
          delete this.pendingCerts[servername];
        }
      });
    } else {
      console.log('Rejected by whitelist function');
    }
    return this.defaultContext;
  }
};

Store.prototype.handleChallenge =  function(req, res) {
  var wellKnownPrefix = '/.well-known/acme-challenge/';
  if (req.url.substring(0, wellKnownPrefix.length) === wellKnownPrefix) {
    var domain = req.headers.host;
    var challenge = req.url.substring(wellKnownPrefix.length);
    if (this.pendingCerts[domain]) {
      var token = this.pendingCerts[domain](challenge);
      //console.log('responding', domain, challenge, token);
      res.writeHead(200);
      res.end(token);
    }
    return true;
  } else {
    return false;
  }
};
