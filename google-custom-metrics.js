/**
 * Copyright (C) 2017 Kinvey, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * upload legacy stackdriver custom metrics to google stackriver
 *
 * 2017-11-28 - AR.
 */

'use strict';

var crypto = require('crypto');
var http = require('http');
var https = require('https');
var Url = require('url');
var util = require('util');
var child_process = require('child_process');
var os = require('os');
var httpRequest = require('microreq');

var googleMetrics;
module.exports = googleMetrics = {
    convertStackdriverUploadToGoogleStackdriver: convertStackdriverUploadToGoogleStackdriver,
    uploadCustomMetricsToGoogleStackdriver: uploadCustomMetricsToGoogleStackdriver,
    getPlatformDetails: getPlatformDetails,

    getGoogleAccessToken: getGoogleAccessToken,
    createGoogleCustomMonitoringJWT:  createGoogleCustomMonitoringJWT,
    signJWT: signJWT,

    httpRequest: httpRequest,

    savedPlatformDetails: null,
};

// only needed for v0.8 support
// if (typeof setImmediate === 'undefined') var setImmediate = process.nextTick;


/*
 * convert a legacy stackdriver upload to an array of google stackdriver uploads
 */
function convertStackdriverUploadToGoogleStackdriver( platformDetails, uploadBody ) {
    if (uploadBody === undefined) {
        uploadBody = platformDetails;
        platformDetails = {};
    }

    // incoming stackdriver body has { timestamp, proto_version, data: [ { name, value, collected_at, instance }, ... ] }
    if (!uploadBody || !uploadBody.data || !uploadBody.data.length) return [];

    var googleMetricsArray = [];
    var timestampOffset = 1;

    // decide how to present the metrics to google, try to associate them to the instance
    var metricsType, instanceName, resourceLabels;
    switch (platformDetails.resource_type) {
    case 'aws_ec2_instance':
    case 'gce_instance':
        // instance types that are supported
        // Include enough details for custom stats to be associated to aws instances
        // Values left undefined will be omitted from the json, and
        // getPlatformDetails left the proper fields undefined for aws and gcp.
        metricsType = platformDetails.type;
        instanceName = platformDetails.instance_name || undefined;
        resourceLabels = {
            instance_id: platformDetails.instance_id,   // aws, gcp
            aws_account: platformDetails.aws_account,   // aws
            region: platformDetails.region,             // aws
            project_id: platformDetails.project_id,     // gcp (from creds)
            zone: platformDetails.zone,                 // gcp
        };
        break;
    default:
        // unknown instance, upload metrics as type 'global' with no resource labels
        // Use the override name from platformDetails, else each legacy sample.instance.
        // If instanceName is null the loop below will use each sample.instance.
        metricsType = 'global';
        instanceName = platformDetails.instance_name || null;
        resourceLabels = undefined;
        break;
    }

    // gather each metric into a separate object
    for (var sampleIdx = 0; sampleIdx < uploadBody.data.length; sampleIdx++) {
        var sample = uploadBody.data[sampleIdx];
        var sampleTimestamp = googleTimestamp(sample.collected_at);

        // platformDetails hostname or omit, if `null` use the legacy aws ec2metadata instance-id
        var instance_name = (instanceName === null) ? sample.instance : instanceName;

        googleMetricsArray.push({
            metric: {
                type: 'custom.googleapis.com/' + sample.name,
                labels: { instance_name: instance_name },
            },
            resource: {
                type: platformDetails.resource_type,            // 'global', 'gce_instance', 'aws_ec2_instance'
                labels: resourceLabels,                         // assembled above
            },
            // metricKind: 'GAUGE',     // default for a new custom metric
            // valueType: 'DOUBLE',     // default for a new metric is to use point.value
            // points: { interval: { startTime: "", endTime: "" }, value: { doubleValue: NN } }
            points: [
                // "When creating a time series, this field must contain exactly one point"
                { interval: { endTime: sampleTimestamp }, value: { doubleValue: sample.value } },
            ],
        });
    }

    // google expects time-sorted samples
    googleMetricsArray.sort(function(m1, m2) {
        return (m1.points[0].interval.endTime <= m2.points[0].interval.endTime) ? -1 : 1;
    })

    // google rejects two samples of the same name with the same timestamp; legacy averaged them.
    // Teak the timestamps to achieve averaging by assigning unique milliseconds to each metric.
    // Works for up to 1000 points per metric.type per second, above which there is the possibility
    // of overlapping the next metrics group (depending on sampling frequency).
    // note: legacy timestamps are all even seconds, ie .000 milliseconds.
    // note: we alrady sorted googleMetrics into ascending timestamp order.
    var lastTimestamps = {};
    for (var sampleIdx=0; sampleIdx<googleMetricsArray.length; sampleIdx++) {
        var sample = googleMetricsArray[sampleIdx];
        var type = sample.metric.type;
        if (sample.points[0].interval.endTime <= lastTimestamps[type]) {
            // only ever less than if timestamps were tweaked; tweak this one too
            sample.points[0].interval.endTime = incrementTimestamp(lastTimestamps[type], 1);
            //sample.points[0].interval.endTime = sample.points[0].interval.endTime.replace(/\d\d\dZ/, '999Z'); -- shows up!
        }
        lastTimestamps[type] = sample.points[0].interval.endTime;
    }

    // split the samples into groups, maintaining the time-sorted order,
    // with no two samples in a group having the same name (metric.type).
    // This "Duplicate TimeSeries encountered.  Only one point can be written
    // per TimeSeries per request." errors.
    var timeSeriesArray = [];
    var groupMetrics = [], groupMetricsNames = {}, groupTimestamp = '';
    for (var sampleIdx = 0; sampleIdx < googleMetricsArray.length; sampleIdx++) {
        var sample = googleMetricsArray[sampleIdx];
        if (groupMetricsNames[sample.metric.type] !== undefined) {
            // name already occurred, flush group, start new group.
            timeSeriesArray.push({ timeSeries: groupMetrics });
            groupMetrics = [];
            groupMetricsNames = {};
        }
        groupMetricsNames[sample.metric.type] = true;
        groupMetrics.push(sample);
    }
    timeSeriesArray.push({ timeSeries: groupMetrics });

    return timeSeriesArray;

    function googleTimestamp( when ) {
        if (typeof when === 'string') return when;
        if (typeof when === 'number' && (when > 1e9 && when < 4e9)) return new Date(when * 1000).toISOString();
        return new Date(when).toISOString();
    }

    function incrementTimestamp( timestamp, ms ) {
        var dt = new Date(timestamp);
        return new Date(dt.getTime() + ms).toISOString();
    }
}

/*
 * upload the batches of metrics to google stackdriver
 * Returns an array with the upload replies.
 */
function uploadCustomMetricsToGoogleStackdriver( creds, metricsBatches, callback ) {
    var accessScope = 'https://www.googleapis.com/auth/monitoring';
    var accessExpireSec = 3600;

    if (!creds.project_id) return callback(new Error("missing creds.project_id"));

    googleMetrics.getGoogleAccessToken(creds, accessScope, accessExpireSec, function(err, accessToken) {
        if (err) return callback(err);

        var uri = {
            url: util.format('https://monitoring.googleapis.com/v3/projects/%s/timeSeries', creds.project_id),
            method: 'POST',
            agent: new https.Agent({ keepAlive: true }),
            headers: {
                'Authorization': 'Bearer ' + accessToken,
            }
        };

        var replies = [];
        function uploadBatches() {
            var body = metricsBatches.shift();
            if (!body) return callback(null, replies);

            googleMetrics.httpRequest(uri, body, function(err, res, reply) {
                if (err) return callback(err);
                replies.push({ statusCode: res.statusCode, body: tryJsonDecode(String(reply)) });
                setImmediate(uploadBatches);
            });
        }

        uploadBatches();
    });
}

/*
 * ask google for an access token to use with the google-stackdriver api
 */
function getGoogleAccessToken( creds, accessScope, accessExpireSec, cb ) {
    try {
        var webtoken = googleMetrics.createGoogleCustomMonitoringJWT(creds, { scope: accessScope, expire: accessExpireSec });
    } catch (err) {
        return cb(err);
    }

    var grantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    var body = util.format('grant_type=%s&assertion=%s', grantType, webtoken);
    var uri = {
        url: "https://www.googleapis.com/oauth2/v4/token",      // needs to be this, not creds.token_uri
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    };
    googleMetrics.httpRequest(uri, body, function(err, res, reply) {
        reply = String(reply);

        if (err) err = err;
        else if (res.statusCode >= 300) err = new Error("http error " + res.statusCode + "\n" + reply);
        else if (reply[0] !== '{') err = new Error("expected json response with token, got " + reply);
        if (err) return cb(err, reply);

        var json = tryJsonDecode(reply);
        if (json instanceof Error) return cb(json, reply);

        var token = json.access_token;  // some docs refer to `id_token`
        cb(null, token);
    });
}

/*
 * create the json web token used to request an api access token
 */
// TODO: inline this into getGoogleAccessToken()
function createGoogleCustomMonitoringJWT( creds, options ) {
    var secondsToExpire = options.expire || 3600;

    var scopeUrl = options.scope;
    if (!scopeUrl) throw new Error("missing options.scope");

    var client_email = creds.client_email || creds.client_id;
    if (!client_email) throw new Error("missing creds.client_email")

    var key = creds.private_key;
    if (!key) throw new Error("missing creds.private_key");

    var nowSec = Math.floor(new Date().getTime() / 1000);
    var jwtHeader = {
        alg: 'RS256',
        typ: 'JWT',
    };

    // all the fields in the jwtClaimSet are required
    var jwtClaimSet = {
        aud: "https://www.googleapis.com/oauth2/v4/token",      // audience; do not change
        iss: client_email,                                      // issuer; client_id also ok
        scope: scopeUrl,                                        // domain/path for which auth_token is valid
        iat: nowSec - 60,                                       // issued at sec, allow 1 min time skew
        exp: nowSec + secondsToExpire,                          // expires at sec
    };

    var webtoken = googleMetrics.signJWT(jwtHeader.alg, jwtHeader, jwtClaimSet, key);
    return webtoken;
}

/*
 * build and cryptographically sign the jwt with a shared secret key.
 * The RS256 key is the entire `private_key` from eg the stackdriver service account credentials,
 * must be in PEM format (with the "-----BEGIN----- ... -----END-----\n" left in).
 * The HS256 key can be any string.
 */
// TODO: rename to `createSignedJWT`
function signJWT( algorithm, header, claimSet, key ) {
    // JWT signature is applied to base64-encoded header '.' body
    // header is typically { alg: 'RS256', typ: 'JWT' }
    // claimSet is the permissions requested, google needs { aud, iss, scope, iat, exp }
    header = encodeBase64url(JSON.stringify(header));
    claimSet = encodeBase64url(JSON.stringify(claimSet));

    var signature;
    switch (algorithm) {
    case 'RS256':
        signature = crypto.createSign('RSA-SHA256').update(header + '.' + claimSet).sign(key);
        break;
    case 'HS256':
        signature = crypto.createHmac('sha256', key).update(header + '.' + claimSet).digest();
        break;
    default:
        throw new Error(algorithm + ": unknown algorithm");
    }
    signature = encodeBase64url(signature);

    // a JWT consists of separately base64url encoded header.claimSet.signature
    return header + '.' + claimSet + '.' + signature;

    function encodeBase64url( str ) {
        // url base64 is almost the same, but no '=' padding and uses symbols [-_] instead of [+/]
        return new Buffer(str).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }
}

function tryJsonDecode( string, fromGce ) {
    try {
        var obj = JSON.parse(string);
        if (fromGce && obj.id && obj.id > Number.MAX_SAFE_INTEGER) {
            // the GCE host metadata contains an overlong integer that overflows Number().
            // Return it as a string, else stats uploads error out due to the mismatch.
            string = String(string);
            var p1 = string.indexOf('"id":');
            var p2 = string.indexOf(',', p1);
            var id = string.slice(p1 + 5, p2).trim();
            obj.id = id;
        }
        return obj;
    }
    catch (e) {
        e.jsonInput = string;
        e.message = 'json error: ' + e.message;
        return e;
    }
}

/*
 * look up details about the virtual environment that is needed to send with the stats
 * If a credentials json is provided, parse that instead for the platform report.
 */
function getPlatformDetails( creds, callerJson ) {
    creds = creds || {};

    // extract details from the callerJson if provided
    if (callerJson) {
        var details = lookUpPlatformDetails(callerJson);
    }
    else {
        // reuse the info if available, else look up the details in the environment
        if (!googleMetrics.savedPlatformDetails) googleMetrics.savedPlatformDetails = lookUpPlatformDetails();

        // return a copy of our saved info
        var details = {};
        for (var k in googleMetrics.savedPlatformDetails) {
            details[k] = googleMetrics.savedPlatformDetails[k];
        }
    }

    // the project_id is added from the creds
    details.project_id = creds.project_id;

    return details;
}

function lookUpPlatformDetails( callerJson ) {
    var json;
    var needJsonDecode = typeof callerJson === 'string' || Buffer.isBuffer(callerJson);

    // AWS
    // Both aws and gcp respond to this url, but only aws with a json document
    // Of them, only aws returns info with /usr/bin/ec2metadata (gcp returns all 'unavailable')
    var awsCmdline = 'curl -s -m 0.050 http://169.254.169.254/latest/dynamic/instance-identity/document';
    json = needJsonDecode && tryJsonDecode(callerJson) || callerJson || tryJsonDecode(_tryExecSync(awsCmdline));
    if (json.instanceId) return {
        resource_type: 'aws_ec2_instance',      // google metrics type for amazon cloud
        instance_id: json.instanceId,           // AWS instance_id
        instance_name: hostname_s(json.hostname),
        aws_account: json.accountId,            // AWS account_id
        region: 'aws:' + json.availabilityZone,
        zone: undefined,
    }


    // GCP
    var gcpCmdline = "curl -s -m 0.050 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true";
    json = needJsonDecode && tryJsonDecode(callerJson, true) || callerJson || tryJsonDecode(_tryExecSync(gcpCmdline), true);
    if (json.id) return {
        resource_type: 'gce_instance',          // google metrics type for google cloud
        instance_id: json.id,                   // GCP instance id 
        instance_name: hostname_s(json.hostname),
        aws_account: undefined,
        region: undefined,
        zone: json.zone.split('/').pop(),       // GCP availability zone
    }

    // backward compatibility
    // some systems may have a patched ec2metadata to provide a unique system id
    var instance_id = _tryExecSync("ec2metadata | grep instance-id").trim().split(' ').pop();

    json = callerJson || {};
    return {
        // on other platforms, send 'global' type metrics
        // note: 'global' metrics cannot associate to the instance_id
        resource_type: json.resource_type || 'global',
        instance_id: json.instance_id || instance_id,
        instance_name: hostname_s(json.hostname),
    };
}

// run the command, return its output
// In case of error, return nothing, the code will know it failed
function _tryExecSync( cmdline ) {
    try { return String(child_process.execSync(cmdline)) }
    catch (err) { return '' }
}

function hostname_s( hostname ) {
    hostname = hostname || os.hostname();
    var dot = hostname.indexOf('.');
    return (dot > 0) ? hostname.slice(0, dot) : hostname;
}
