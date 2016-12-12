'use strict';
var log = require('./../logger')().log;
var utils = require('./../utils');
var fs = require('fs');
var path = require('path');
var storj = require('storj-lib');
var assert = require('assert');
var async = require('async');
var through = require('through');

/**
 * Interface for downloading files from the Storj Network
 * @constructor
 * @license AGPL-3.0
 * @param {BridgeClient} client - Authenticated Bridge Client with Storj API.
 * @param {String} keypass - Password for unlocking keyring.
 * @param {String} options.bucket - Bucket files are uploaded to.
 * @param {String} options.fileid - File id listed in bucket
 * @param {String} options.env.exclude - Nodes to exclude when downloading.
 * @param {String} options.filepath - Path of files being uploaded.
 */
function Downloader(client, fileid, bucketid, options) {
  if (!(this instanceof Downloader)) {
    return new Downloader(client, fileid, bucketid, options);
  }

  this.bucket = bucketid;
  this.fileid = fileid;
  this.filepath = options.filepath;
  this.client = client();
  this.keypass = options.keypass;
  this.fileMeta = null;
  this.exclude = options.env.exclude;

  this._validate();
}

/**
 * Validate everything required was passed to the constructor
 * @private
 */
Downloader.prototype._validate = function() {
  // Don't overwrite a file that already exists
  // Make sure if the path ends with the folder, that folder exists
  if (storj.utils.existsSync(this.filepath)) {
    assert(
      !fs.statSync(this.filepath).isFile(),
      'Refusing to overwrite file at ' + this.filepath
    );
  } else if (this.filepath.slice(-1) === path.sep) {
    throw new Error(this.filepath + ' is not an existing folder');
  }

  // Make sure the subdirectory exists
  assert(
    storj.utils.existsSync(path.dirname(this.filepath)),
      path.dirname(this.filepath) + ' is not an existing folder'
  );
};

/**
 * Removes the initial ISOString from a file name
 * @param {String} fileName - file name
 * @returns {String}
 * @private
 */
Downloader.prototype._stripISOString = function(fileName){
  var re = /^\(\d{4}-\d{2}-\d{2}T\d{2};\d{2};\d{2}.\d{3}Z\)-/g;
  return fileName.replace(re, '');
};

/**
 *  Get file metadata from bridge
 * @private
 */
Downloader.prototype._getInfo = function(callback) {
  var self = this;

  this.client.getFileInfo(this.bucket, this.fileid, function(err, file) {
    if (err) {
      return callback(err);
    }
    log(
      'info',
      'Name: %s, Type: %s, Size: %s bytes, ID: %s',
      [file.filename, file.mimetype, file.size, file.id]
    );
    self.fileMeta = file;
    self.fileMeta.filename = self._stripISOString( file.filename );
    return callback(null);
  });
};

/**
 * Determine if the filepath given was a folder or a file name
 * @private
 */
Downloader.prototype._determineSaveLocation = function(callback) {
  if (this.fileMeta === null) {
    return callback(
      new Error(
        'file ' + this.fileid + ' does not exist in bucket ' + this.bucket
      )
    );
  }

  // If _validate has successfully passed by this point, we know the following:
  //  * The parent directory of this.filepath exists
  //  * If this.filepath is a file, this file does not yet exist
  //  * If this.filepath is a directory, this directory already exists

  // If the filepath already exists, it must be a directory
  // Otherwise, it must be a file
  if (storj.utils.existsSync(this.filepath)) {
    // use the file name as the name of the file to be downloaded to
    var fullpath = path.join(this.filepath,this.fileMeta.filename);

    // Make sure fullpath doesn't already exist
    if (storj.utils.existsSync(fullpath)) {
      return callback(
        new Error(
          'Refusing to overwrite file at ' + fullpath
        )
      );
    }

    this.destination = fullpath;
  } else {
    this.destination = this.filepath;
  }

  return callback(null);
};

/**
 * set this.keyring using this.keypass
 * @private
 */
Downloader.prototype._getKeyRing = function(callback) {
  var self = this;

  utils.getKeyRing(this.keypass, function(keyring) {
    self.keyring = keyring;
    return callback(null);
  });
};

/**
 * Create file stream for downloading file
 * @private
 */
Downloader.prototype._createFileStream = function(callback) {
  var self = this;
  this.target = fs.createWriteStream(this.destination);

  this.target.on('finish', function() {
    log('info', 'File downloaded and written to %s.', [self.destination]);
    self.finalCallback(null, self.destination);
  }).on('error', function(err) {
    return callback(err);
  });

  this.client.createFileStream(
    this.bucket,
    this.fileid,
    {exclude: this.exclude.split(',')},
    callback
  );
};

/**
 * Handle the file stream
 * @param stream - filestream
 * @private
 */
Downloader.prototype._handleFileStream = function(stream, callback) {
  var self = this;
  var received = 0;
  var secret;

  if (stream.encryptionKey) {
    var fileKey = storj.DeterministicKeyIv.getDeterministicKey(
      Buffer.from(stream.encryptionKey, 'hex'),
      Buffer.from(self.fileid, 'hex')
    );
    secret = new storj.DeterministicKeyIv(fileKey, self.fileid);
  } else {
    secret = this.keyring.get(this.fileid, this.bucket);
  }

  if (!secret) {
    return callback(new Error('No decryption key found in key ring!'));
  }

  var decrypter = new storj.DecryptStream(secret);

  stream.on('error', function(err) {
    log('warn', 'Failed to download shard, reason: %s', [err.message]);
    fs.unlink(self.destination, function(unlinkFailed) {
      if (unlinkFailed) {
        return callback(new Error('Failed to unlink partial file.'));
      }

      if (!err.pointer) {
        return callback(new Error('Failed to download file'));
      }

      log('info', 'Retrying download from other mirrors...');
      var exclude = self.exclude.split(',');
      exclude.push(err.pointer.farmer.nodeID);
      self.exclude = exclude.join(',');
      self.start(self.finalCallback);
    });
  }).pipe(through(function(chunk) {
    received += chunk.length;
    log('info', 'Received %s of %s bytes', [received, stream._length]);
    this.queue(chunk);
  })).pipe(decrypter).pipe(this.target);
};

/**
 * Aggregator function for complete download process.
 * @param {Function} finalCallback - function for handling errors and when done.
 */
Downloader.prototype.start = function(finalCallback) {
  var self = this;
  this.finalCallback = finalCallback;

  async.waterfall([
    function _getInfo(callback) {
      self._getInfo(callback);
    },
    function _determineSaveLocation(callback) {
      self._determineSaveLocation(callback);
    },
    function _getKeyRing(callback) {
      self._getKeyRing(callback);
    },
    function _createFileStream(callback) {
      self._createFileStream(callback);
    },
    function _handleFileStream(stream, callback) {
      self._handleFileStream(stream, callback);
    }
  ], function (err, filepath) {
    if (err) {
      if (storj.utils.existsSync(self.destination) && self.destination) {
        log('info', 'Removing unfinished file: %s', self.destination);
        fs.unlinkSync(self.destination);
      }
    }
    finalCallback(err, filepath);
  });

};

module.exports = Downloader;
