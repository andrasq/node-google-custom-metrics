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
 * 2017-11-28 - AR.
 */

'use strict';

var gm = require('./');

var qmock = require('qnit').qmock;
var https = require('https');
var http = require('http');
var os = require('os');
var child_process = require('child_process');

if (typeof setImmediate === 'undefined') var setImmediate = process.nextTick;


// test key generated with ssh-keygen
var somePrivateKey = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA8C18zCAHnQoqsSZMmnniHDKovLNrvaKHHvLNZFbksk7hWLeB',
    'dJk+sh9etpHVKNTfwplvXbfaHFy7hIuWdsxw1kAw6GlQj45Gd68qUMt4HKzssTfF',
    'gZzRfRTYxBafBl1lwcBqYxLC1owWusqkiKShxRhf4CSQYUqJRFIcukqiFLOm+rnu',
    'U9Ye1Zidu7rwM9OiRA38HflVKTmZqHc8c4D8+RfSSC2Xv6oF/Alm88sxBfOyAQwC',
    'b5yJp3p1CUlEe4X9pTzljKC9K0DBsFTvHbI1JLSlQ/bdTShHLpMlhzTNznf9OVHe',
    'nZIZL3L7R6Sr7GHWjjaTA8HWnvXgVrX3rf5NbwIDAQABAoIBAHMxzf51ilFG1A0d',
    'SnZ46PsPTSEciRtuPZKZb+ulRZFEBg8wDJYo/goew6WbMnqgByZlwyVXDfS2gXXk',
    'IWmfSqtoJE0EXhBMc/3pdMlFnblbMzcYgdFVrqBohEMgemtqFmkkaaJVGEAg9rHm',
    'iZ3EIJbQxwNRZjJTtpyfKYosS6rTRetc3nuvIM6d6/6xOF0QbfQvPWRjRWAR1mXc',
    'OYamf6YyI6L9SERAJVpITGCELkzJjno/K6I6zaEIhfAe8f57j2YlucHATcCXti2w',
    'Dg/whipfndSvDz9+BiKZYAK3fmRzEWv0e8YdiEt1O9w7PxkwUNDauCek8WY1cP02',
    'D0qo5BkCgYEA+6oE09f4Hi4l8b5B9BnQv01T8WuxdLN/tLgF5eDNU7wx12s9wXSN',
    'DXo7WQ0FDxQSHmB9t+DmfuFH7awB8JNWZVD9dtsoF6nvLVau+GNaswkqYk7bwDiM',
    'HfB3gCAMpREaNkg3btvNAyRxbErXb24dbvzMnu5WKp2T43UIfIkTWB0CgYEA9FDO',
    'kFXq+wdIwZmhOa/BEoFXXFRvySwqP9UINVQ6A+kzd1sZ2fp7Ld10pAboJyIOT6oe',
    'v27jQqt/xQUJN+UtGH+ZUmd4u2PGhoSVS18pWoTZBgLauaqmfboA0FSyoLSwWnFz',
    'Pok2mzPWW8nh8+ZEQgePGXzNup+J0exUe+2oPfsCgYB1fFrClwlC9aJLJ9ncXgzg',
    'sfXlN7RhWcbdlCdUuMzCMZJHEc6DuKh8yTpZiUV6U5Fd0wf9xqV0SDFvGCTTrcTg',
    'iZ26VfdyjKeWz+fhF2jpOfcqa8wVAZEQDQmMq+mbSc+l1bLjMwOTWvkEaDAI2iwt',
    'eyD/dR6OyH+Y6TLsCIYaVQKBgQCV1e0pZhgLxmbfnRnc6CYv9DUgwgQgy75JkZxM',
    'IJDID0BqJewP3GepNFUxt66vOVqvjvT2kMo9/DILIdCKgDoM+UyN1jmcK0/49d0d',
    '8YnKIwl6f0unbLpZBzcyjY9Tsh0qCsQUCVD9FGiVuJWj4IfiOwKPLhR6LRf4L8mM',
    'i6+P+wKBgEJQNHiSLtEXSzhGGoubofmjSTEiquRm1VF2flSMTzq+WHB1IxTSu+AX',
    '6CvMH316D5YFZy7v9khLOTZ40gb939sBmrYwOyHuWezh5fKXGMFJecAHJAWoeHj6',
    'KnL1rSCmIG+aysdwf82coCHOUYEobhDY825DVqXget21DFXpUbeG',
    '-----END RSA PRIVATE KEY-----',
].join('\n');


module.exports = {
    'package': {
        'should export api functions': function(t) {
            t.equal(typeof gm.convertStackdriverUploadToGoogleStackdriver, 'function');
            t.equal(typeof gm.uploadCustomMetricsToGoogleStackdriver, 'function');
            t.equal(typeof gm.getPlatformDetails, 'function');
            t.done();
        },

        'should export httpRequest': function(t) {
            t.equal(typeof gm.httpRequest, 'function');
            t.equal(gm.httpRequest.length, 3);
            t.done();
        },

        'should export helper functions': function(t) {
            // note: helper names and function signatures subject to change
            t.equal(typeof gm.getGoogleAccessToken, 'function');
            t.equal(typeof gm.createGoogleCustomMonitoringJWT, 'function');
            t.equal(typeof gm.signJWT, 'function');
            t.done();
        },
    },

    'api': {
        'getPlatformDetails': {
            'beforeEach': function(done) {
                done();
            },

            'should accept creds': function(t) {
                gm.savedPlatformDetails = null;
                var info = gm.getPlatformDetails({ project_id: 123456 });
                t.equal(info.project_id, 123456);
                t.done();
            },

            'should accept aws json object': function(t) {
                gm.savedPlatformDetails = { details: 'some details' };
                var info = gm.getPlatformDetails({ project_id: 123456 }, { instanceId: 1, hostname: 'some host', availabilityZone: 'north-east' });
                t.equal(info.resource_type, 'aws_ec2_instance');
                t.equal(info.region, 'aws:north-east');
                t.equal(info.instance_name, 'some host');
                t.equal(info.project_id, 123456);
                t.done();
            },

            'should accept aws json string and Buffer': function(t) {
                gm.savedPlatformDetails = { details: 'some details' };
                var info = gm.getPlatformDetails({ project_id: 123456 }, JSON.stringify({ instanceId: 1, availabilityZone: 'north-east' }));
                t.equal(info.resource_type, 'aws_ec2_instance');
                var info = gm.getPlatformDetails({ project_id: 123456 }, new Buffer(JSON.stringify({ instanceId: 1, availabilityZone: 'north-east' })));
                t.equal(info.resource_type, 'aws_ec2_instance');
                t.done();
            },

            'should accept gce json object': function(t) {
                gm.savedPlatformDetails = { details: 'some details' };
                var info = gm.getPlatformDetails({ project_id: 123456 }, { id: 1, hostname: 'some other host', zone: 'north-east-A' });
                t.equal(info.resource_type, 'gce_instance');
                t.equal(info.zone, 'north-east-A');
                t.equal(info.instance_name, 'some other host');
                t.equal(info.project_id, 123456);
                t.done();
            },

            'should accept other json object': function(t) {
                gm.savedPlatformDetails = { details: 'some details' };
                var info = gm.getPlatformDetails({ project_id: 123456 }, { resource_type: 'other type', hostname: 'some other other host' });
                t.equal(info.resource_type, 'other type');
                t.equal(info.instance_name, 'some other other host');
                t.equal(info.project_id, 123456);
                t.done();
            },

            'should probe for aws': function(t) {
                var awsProbed = false;

                var awsInfo = {
                    instanceId: 'some-aws-instance-id',
                    accountId: 'some-aws-account-id',
                    availabilityZone: 'some-aws-region',
                };

                function mockAwsShell(cmdline) { return (/169.254.169.254/.test(cmdline)) ? JSON.stringify(awsInfo) : "{}" }
                var spy = t.stub(child_process, 'execSync', mockAwsShell);
                gm.savedPlatformDetails = null;
                var awsDetails = gm.getPlatformDetails();
                spy.restore();

                t.contains(awsDetails, {
                    resource_type: 'aws_ec2_instance',
                    instance_id: awsInfo.instanceId,
                    aws_account: awsInfo.accountId,
                    region: 'aws:' + awsInfo.availabilityZone,
                })

                t.done();
            },

            'should probe for gce': function(t) {
                var gceProbed = false;

                var gceInfo = {
                    id: 'some-gce-instance',
                    zone: 'some/gce-zone',
                };

                function mockGceShell(cmdline) { return (/metadata.google.internal/.test(cmdline)) ? JSON.stringify(gceInfo) : "{}" }
                var spy = t.stub(child_process, 'execSync', mockGceShell);
                gm.savedPlatformDetails = null;
                var gceDetails = gm.getPlatformDetails();
                spy.restore();

                t.contains(gceDetails, {
                    resource_type: 'gce_instance',
                    instance_id: 'some-gce-instance',
                    zone: 'gce-zone',
                })

                t.done();
            },

            'should return overlong gce host id': function(t) {
                var gceInfo =
                    '{"id":1234123412341234123,"hostname":"andras.c.gc-kvy-mt-us2.internal","zone":"projects/764585844340/zones/us-east1-d"}';
                gm.savedPlatformDetails = null;
                var gceDetails = gm.getPlatformDetails({}, gceInfo);
                t.strictEqual(gceDetails.instance_id, "1234123412341234123");
                t.done();
            },

            'should return hostname': function(t) {
                // this test broke on travis-ci when they changed to containers that mimic both AWS and GC
                // Both ec2metadata and http://metadata.google.internal/computeMetadata/ return info now, and
                // since the gce metadata contains the hostname os.hostname is not called.
                t.skip();
                var stub = t.stubOnce(os, 'hostname', function() { return 'some-host.name.com' });
                gm.savedPlatformDetails = null;
                var info = gm.getPlatformDetails();
                t.equal(info.instance_name, 'some-host');
                t.done();
            },

            'should return hostname from details': function(t) {
                gm.savedPlatformDetails = null;
                var info = gm.getPlatformDetails({}, { hostname: 'some-other-host.name.com'});
                t.equal(info.resource_type, 'global');
                t.equal(info.instance_name, 'some-other-host');
                var info = gm.getPlatformDetails({}, JSON.stringify({ hostname: 'some-other-host.name.com'}));
                t.equal(info.resource_type, 'global');
                t.equal(info.instance_name, 'some-other-host');
                t.done();
            },

            'should reuse saved platform details': function(t) {
                gm.savedPlatformDetails = { detail: 'some-detail' };
                var info = gm.getPlatformDetails();
                t.contains(info, { detail: 'some-detail' });
                t.done();
            },
        },

        'convertStackdriverUploadToGoogleStackdriver': {
            'beforeEach': function(done) {
                this.oldUpload = {
                    timestamp: 1500000010,
                    proto_version: 1,
                    data: [
                        // will be sorted into time-ascending order
                        { name: 'metric2-name', collected_at: 1500000002, value: 1.2, instance: 'i-00x2' },
                        { name: 'metric3-name', collected_at: 1500000003, value: 1.3, instance: 'i-00x3' },
                        { name: 'metric1-name', collected_at: 1500000001, value: 1.1, instance: 'i-00x1' },
                    ]
                };
                done();
            },

            'should return an array of upload batches': function(t) {
                var oldUpload = this.oldUpload;
                oldUpload.data = [];
                var newUploadBatches = gm.convertStackdriverUploadToGoogleStackdriver(oldUpload);
                t.ok(Array.isArray(newUploadBatches));
                t.equal(newUploadBatches.length, 0);
                t.done()
            },

            'should convert object to new format': function(t) {
                var oldUpload = this.oldUpload;
                var newUploadBatches = gm.convertStackdriverUploadToGoogleStackdriver(oldUpload);
                // converted upload will be time-order sorted
                var expectedNewUploads = [
                    { timeSeries: [
                        {
                            metric: { type: 'custom.googleapis.com/metric1-name', labels: { instance_name: 'i-00x1' } },
                            resource: { type: undefined, labels: undefined },
                            points: [ { interval: { endTime: '2017-07-14T02:40:01.000Z' }, value: { doubleValue: 1.1 } } ]
                        },
                        {
                            metric: { type: 'custom.googleapis.com/metric2-name', labels: { instance_name: 'i-00x2' } },
                            resource: { type: undefined, labels: undefined },
                            points: [ { interval: { endTime: '2017-07-14T02:40:02.000Z' }, value: { doubleValue: 1.2 } } ]
                        },
                        {
                            metric: { type: 'custom.googleapis.com/metric3-name', labels: { instance_name: 'i-00x3' } },
                            resource: { type: undefined, labels: undefined },
                            points: [ { interval: { endTime: '2017-07-14T02:40:03.000Z' }, value: { doubleValue: 1.3 } } ]
                        }
                    ] }
                ];

                t.deepStrictEqual(newUploadBatches, expectedNewUploads);
                var batch1 = newUploadBatches[0];

                t.ok(Array.isArray(batch1.timeSeries));
                t.equal(batch1.timeSeries.length, 3);

                var sample1 = batch1.timeSeries[0];
                var sample2 = batch1.timeSeries[1];
                t.equal(typeof sample1.metric, 'object');
                t.equal(typeof sample1.metric.type, 'string');
                t.equal(typeof sample1.metric.labels, 'object');
                t.contains(sample1.metric.type, 'custom.googleapis.com/metric1-name');
                t.contains(sample2.metric.type, 'custom.googleapis.com/metric2-name');
                t.equals(sample1.metric.labels.instance_name, 'i-00x1');
                t.equals(sample2.metric.labels.instance_name, 'i-00x2');

                t.equal(typeof sample1.resource, 'object');

                t.equal(typeof sample1.points, 'object');
                t.ok(Array.isArray(sample1.points));
                t.equal(sample1.points.length, 1);
                t.equal(typeof sample1.points[0].value, 'object');
                t.equal(sample1.points[0].value.doubleValue, 1.1);
                t.equal(sample2.points[0].value.doubleValue, 1.2);
                t.equal(sample1.points[0].interval.endTime, '2017-07-14T02:40:01.000Z');
                t.equal(sample2.points[0].interval.endTime, '2017-07-14T02:40:02.000Z');

                t.done();
            },

            'should move same-name samples into different batches': function(t) {
                var oldUpload = this.oldUpload;

                // different names, one batch
                var batches = gm.convertStackdriverUploadToGoogleStackdriver(oldUpload);
                t.equal(batches.length, 1);

                // two samples of the same name, two batches
                oldUpload.data[0].name = 'metric-name';
                oldUpload.data[1].name = 'metric-name';
                var batches = gm.convertStackdriverUploadToGoogleStackdriver(oldUpload);
                t.equal(batches.length, 2);

                t.done();
            },

            'should adjust identical timestamps to have samples be averaged': function(t) {
                var oldUpload = {
                    timestamp: 1500000010,
                    proto_version: 1,
                    data: [
                        { name: 'metric-name', collected_at: 1500000000, value: 1.1 },
                        { name: 'metric-name', collected_at: 1500000000, value: 1.2 },
                    ]
                };
                var batches = gm.convertStackdriverUploadToGoogleStackdriver(oldUpload);
                t.equal(batches[0].timeSeries[0].points[0].interval.endTime, '2017-07-14T02:40:00.000Z');
                t.equal(batches[1].timeSeries[0].points[0].interval.endTime, '2017-07-14T02:40:00.001Z');
                t.done();
            },

            'should override instance_name from platformDetails': function(t) {
                var batches = gm.convertStackdriverUploadToGoogleStackdriver({ instance_name: 'test-instance' }, this.oldUpload);
                t.equal(batches[0].timeSeries[0].metric.labels.instance_name, 'test-instance');
                t.equal(batches[0].timeSeries[1].metric.labels.instance_name, 'test-instance');
                t.done();
            },

            'should set aws resource details from platformDetails': function(t) {
                var platformDetails = {
                    resource_type: 'aws_ec2_instance',
                    instance_id: 'some-instance-id',
                    aws_account: 'some-aws-account-id',
                    region: 'some-aws-region',
                    project_id: 'some-gcp-project-id',
                };
                var batches = gm.convertStackdriverUploadToGoogleStackdriver(platformDetails, this.oldUpload);
                t.equal(batches[0].timeSeries[0].resource.type, 'aws_ec2_instance');
                t.contains(batches[0].timeSeries[0].resource.labels, {
                    instance_id: 'some-instance-id',
                    aws_account: 'some-aws-account-id',
                    region: 'some-aws-region',
                    project_id: 'some-gcp-project-id',
                })
                t.equal(batches[0].timeSeries[1].resource.type, 'aws_ec2_instance');
                t.contains(batches[0].timeSeries[1].resource.labels, {
                    instance_id: 'some-instance-id',
                    aws_account: 'some-aws-account-id',
                    region: 'some-aws-region',
                    project_id: 'some-gcp-project-id',
                })
                t.done();
            },

            'edge cases': {
                'should accept string timestamps in old upload': function(t) {
                    var oldUpload = this.oldUpload;
                    oldUpload.data[0].collected_at = '2017-07-14T02:40:02.002Z';
                    oldUpload.data[1].collected_at = '2017-07-14T02:40:03.003Z';
                    oldUpload.data[2].collected_at = '2017-07-14T02:40:01.001Z';

                    var batches = gm.convertStackdriverUploadToGoogleStackdriver(oldUpload);
                    t.equal(batches[0].timeSeries[0].points[0].interval.endTime, '2017-07-14T02:40:01.001Z');
                    t.equal(batches[0].timeSeries[1].points[0].interval.endTime, '2017-07-14T02:40:02.002Z');
                    t.equal(batches[0].timeSeries[2].points[0].interval.endTime, '2017-07-14T02:40:03.003Z');

                    t.done();
                },

                'should accept millisecond timestamps in old upload': function(t) {
                    var oldUpload = this.oldUpload;
                    oldUpload.data[0].collected_at *= 1000;
                    oldUpload.data[1].collected_at *= 1000;
                    oldUpload.data[2].collected_at *= 1000;

                    var batches = gm.convertStackdriverUploadToGoogleStackdriver(oldUpload);
                    t.equal(batches[0].timeSeries[0].points[0].interval.endTime, '2017-07-14T02:40:01.000Z');
                    t.equal(batches[0].timeSeries[1].points[0].interval.endTime, '2017-07-14T02:40:02.000Z');
                    t.equal(batches[0].timeSeries[2].points[0].interval.endTime, '2017-07-14T02:40:03.000Z');

                    t.done();
                },

                'should return overlong gce host id even if no max_safe_integer defined': function(t) {
                    // cannot test if 'use strict': Number.MAX_SAFE_INTEGER cannot be deleted, altered or redefined
                    var processVersion = process.version;

                    Object.defineProperty(process, 'version', { value: 'v0.10.42', writable: true });
                    t.unrequire('./google-custom-metrics');
                    var myGm = require('./google-custom-metrics');
                    var gceInfo =
                        '{"id":1234123412341234123,"hostname":"andras.c.gc-kvy-mt-us2.internal","zone":"projects/764585844340/zones/us-east1-d"}';
                    myGm.savedPlatformDetails = null;
                    var gceDetails = myGm.getPlatformDetails({}, gceInfo);
                    process.version = processVersion;

                    t.strictEqual(gceDetails.instance_id, "1234123412341234123");
                    t.done();
                },
            },
        },

        'uploadCustomMetricsToGoogleStackdriver': {
            'should use token from getGoogleAccessToken in the body uploads httpRequest': function(t) {
                var spy = t.stubOnce(gm, 'getGoogleAccessToken', function(creds, scope, expire, cb) { return cb(null, 'some-Access-Token') });
                var httpSpy = t.spy(gm, 'httpRequest', function(uri, body, cb) { return cb(null, { statusCode: 200 }, '{}') });
                gm.uploadCustomMetricsToGoogleStackdriver({ project_id: 'someId' }, [ 'batch 1 body', 'batch 2 body' ], function(err, replies) {
                    httpSpy.restore();
                    t.equal(httpSpy.callCount, 2);
                    t.equal(httpSpy.getAllArguments()[0][1], 'batch 1 body');
                    t.equal(httpSpy.getAllArguments()[1][1], 'batch 2 body');
                    t.contains(httpSpy.callArguments[0].headers['Authorization'], 'some-Access-Token');
                    t.done();
                })
            },

            'errors': {
                'should require creds.project_id': function(t) {
                    gm.uploadCustomMetricsToGoogleStackdriver({}, [], function(err, replies) {
                        t.ok(err);
                        t.contains(err.message, 'missing creds.project_id');
                        t.done();
                    })
                },

                'should return token error': function(t) {
                    t.stubOnce(gm, 'getGoogleAccessToken', function(creds, scope, expire, cb) { return cb(new Error('tok error')) });
                    gm.uploadCustomMetricsToGoogleStackdriver({ project_id: 'someId' }, [], function(err, replies) {
                        t.ok(err);
                        t.contains(err.message, 'tok error');
                        t.done();
                    })
                },

                'should return http error': function(t) {
                    var spy = t.stubOnce(gm, 'getGoogleAccessToken', function(creds, scope, expire, cb) { return cb(null, 'some-Access-Token') });
                    var httpSpy = t.stubOnce(gm, 'httpRequest', function(uri, body, cb) { return cb(new Error('http error')) });
                    gm.uploadCustomMetricsToGoogleStackdriver({ project_id: 'someId' }, [ 'batch 1 body' ], function(err, replies) {
                        t.ok(err);
                        t.equal(err.message, 'http error');
                        t.done();
                    })
                },
            },
        },
    },

    'helpers': {
        before: function(done) {
            this.mockCreds = {
                client_email: 'someEmail',
                private_key: somePrivateKey,
            };
            this.mockOptions = {
                scope: 'scopeUrl',
                expire: 1234,
            };
            done();
        },

        'getGoogleAccessToken': {
            'should call httpRequest': function(t) {
                var spy = t.stubOnce(gm, 'httpRequest');
                gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {});
                setTimeout(function() {
                    var uri = spy.callArguments[0];
                    var body = spy.callArguments[1];
                    t.contains(uri.url, 'googleapis.com/oauth2/v4/');
                    t.contains(uri.method, 'POST');
                    t.contains(body, 'grant_type=');
                    t.contains(body, 'assertion=');
                    t.done();
                }, 3);
                
            },

            'should call createGoogleCustomMonitoringJWT and return granted token': function(t) {
                var spy = t.spyOnce(gm, 'createGoogleCustomMonitoringJWT');
                var requestBody;
                t.stubOnce(gm, 'httpRequest', function(uri, body, cb) {
                    t.contains(body, spy.callReturn);
                    t.contains(body, 'jwt-bearer');
                    t.contains(body, 'assertion=' + spy.callReturn);
                    requestBody = body;
                    return cb(null, { statusCode: 200 }, new Buffer('{"access_token":"some-base64-string"}'))
                });
                gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {
                    t.equal(spy.callCount, 1);
                    t.equal(token, 'some-base64-string');
                    t.done();
                })
            },

            'should extract access_token': function(t) {
                t.stubOnce(gm, 'httpRequest', function(uri, body, cb) { return cb(null, {}, new Buffer('{"access_token":"123-45"}')) });
                gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {
                    t.equal(token, '123-45');
                    t.done();
                })
            },

            'errors': {
                'should return jwt error': function(t) {
                    t.stubOnce(gm, 'createGoogleCustomMonitoringJWT', function() { throw new Error('jwt error') });
                    gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {
                        t.ok(err);
                        t.equal(err.message, 'jwt error');
                        t.done();
                    })
                },

                'should return http.request error': function(t) {
                    t.stubOnce(gm, 'httpRequest', function(uri, body, cb) { return cb(new Error('request error')) });
                    gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {
                        t.ok(err);
                        t.equal(err.message, 'request error');
                        t.done();
                    })
                },

                'should return non-json response error': function(t) {
                    t.stubOnce(gm, 'httpRequest', function(uri, body, cb) { return cb(null, {}, new Buffer('non-json string')) });
                    gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {
                        t.ok(err);
                        t.contains(err.message, 'expected json response with token');
                        t.done();
                    })
                },

                'should return broken json response error': function(t) {
                    t.stubOnce(gm, 'httpRequest', function(uri, body, cb) { return cb(null, {}, new Buffer('{"a":1')) });
                    gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {
                        t.ok(err);
                        t.ok(err instanceof SyntaxError);
                        t.contains(err.message, 'json error: ');
                        t.contains(err.message, 'Unexpected end of');
                        t.done();
                    })
                },

                'should return http error response as error': function(t) {
                    var spy = t.stubOnce(gm, 'httpRequest', function(uri, body, cb) { return cb(null, { statusCode: 444.5 }, new Buffer('{"access_token":"1234"}')) });
                    gm.getGoogleAccessToken(this.mockCreds, 'someScopeUrl', 777, function(err, token) {
                        t.ok(err);
                        t.contains(err.message, 'http error 444.5');
                        t.done();
                    })
                },
            },
        },

        'createGoogleCustomMonitoringJWT': {
            'should call signJWT': function(t) {
                var spy = t.spyOnce(gm, 'signJWT');
                var jwt = gm.createGoogleCustomMonitoringJWT(this.mockCreds, this.mockOptions);
                t.equal(spy.callCount, 1);
                t.done();
            },

            'should prepare a header': function(t) {
                var spy = t.spyOnce(gm, 'signJWT');
                var jwt = gm.createGoogleCustomMonitoringJWT(this.mockCreds, this.mockOptions);
                var header = jwt.split('.')[0];
                header = JSON.parse(decode_base64url(header));
                t.deepEqual(header, { alg: 'RS256', typ: 'JWT' });
                t.done();
            },

            'should prepare a claim set': function(t) {
                var nowSec = Math.floor(new Date().getTime() / 1000);
                var jwt = gm.createGoogleCustomMonitoringJWT(this.mockCreds, this.mockOptions);
                var parts = jwt.split('.');
                t.deepEqual(JSON.parse(decode_base64url(parts[0])), {"alg":"RS256","typ":"JWT"});

                var claimSet = JSON.parse(decode_base64url(parts[1]));
                var claimSetFields = Object.keys(claimSet);
                t.deepEqual(claimSetFields, [ 'aud', 'iss', 'scope', 'iat', 'exp' ]);

                t.contains(claimSet.aud, 'googleapis.com/oauth2/v4/token');
                t.contains(claimSet.iss, this.mockCreds.client_email);
                t.contains(claimSet.scope, this.mockOptions.scope);
                t.ok(claimSet.iat >= nowSec - 60);
                t.ok(claimSet.exp >= nowSec + 1234);
                t.ok(claimSet.exp < nowSec + 1240);

                t.done();
            },

            'errors': {
                'should require scopeUrl': function(t) {
                    var creds = this.mockCreds;
                    t.throws(function() { gm.createGoogleCustomMonitoringJWT(creds, {}) });
                    t.done();
                },

                'should require client_email': function(t) {
                    var creds = { private_key: somePrivateKey };
                    var options = this.mockOptions;
                    t.throws(function() { gm.createGoogleCustomMonitoringJWT(creds, options) });
                    t.done();
                },

                'should require private_key': function(t) {
                    var creds = { client_email: 'someEmail' };
                    var options = this.mockOptions;
                    t.throws(function() { gm.createGoogleCustomMonitoringJWT(creds, options) });
                    t.done();
                },
            }
        },

        'signJWT': {
            'should generate correct signature': function(t) {
                var header = { alg: 'RS256', typ: 'JWT' };
                var claimSet = { field1: 1, field2: 2 };

                var jwt = gm.signJWT('RS256', header, claimSet, somePrivateKey);
                var parts = jwt.split('.');
                t.equal(parts.length, 3);
                t.equal(decode_base64url(parts[0]), '{"alg":"RS256","typ":"JWT"}');
                t.equal(decode_base64url(parts[1]), '{"field1":1,"field2":2}');

                // compare to signature computed with 'require("jwt-simple").encode({field1:1, field2:2}, require("fs").readFileSync("./out"), "RS256")'
                var expectedSignature =
'ZYr-xBS8neno3QOIV0nMBtxvmJvijWhd2v7xqKhbmrrTvf1ekurJoAkoC-II2p_SJay3YdapusWz_Y0FhBj2elMLTFP3hS4XuXYn' +
'KBCZ5G55XLSnFrr0l69e-d0TH5uynjzr4ZByNpju5E4MdI7YkkM7G6jULSa_zSYsZNBGpdqKXzxA2PLhAriNAhqaWjsvyC48YNJj' +
'ZC-wSzo-jJXKR-znyIxCmI6HBY5HcNXt83NWW8aCPsW6N1BmN_x3IC2iec8dzjB77vHjcXtD24oFVPSFMJjHeykFAynaV3zBIWu1' +
'wQ-HaxyQxoGmizSX7zntW8giC1IUX30vsmK28HPk8A';
                t.equal(parts[2], expectedSignature);
                t.done();

                var jwt2 = gm.signJWT('HS256', { alg: 'HS256', typ: 'JWT' }, claimSet, "hsaKey");
                t.equal(jwt2, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWVsZDEiOjEsImZpZWxkMiI6Mn0.R4M0aB2gxGnULeScQ5q819C1OKZkJX0yPzC7PD--CyI');
                var parts = jwt2.split('.');
                t.equal(parts[0], 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
                t.equal(parts[1], 'eyJmaWVsZDEiOjEsImZpZWxkMiI6Mn0');
                t.equal(parts[2], 'R4M0aB2gxGnULeScQ5q819C1OKZkJX0yPzC7PD--CyI');
            },

            'should throw on unrecognized algorithm': function(t) {
                try { gm.signJWT('unknown_algorithm', {}, {}, "key") }
                catch (err) {
                    t.contains(err.message, 'unknown algorithm');
                    t.done();
                }
            },
        },
    },
}


var events = require('events');
var util = require('util');

function MockReq( ) {
    events.EventEmitter.call(this);
    this.written = [];
    var self = this;
    this.write = function(chunk) { self.written.push(chunk) };
    this.end = function() {};
}
util.inherits(MockReq, events.EventEmitter);

function MockRes( ) {
    events.EventEmitter.call(this);
}
util.inherits(MockRes, events.EventEmitter);

// mock the next http.request to send a response ms milliseconds from now
function mockHttpRequest( http_https, t, ms ) {
    var mockReq = new MockReq();
    var mockRes = new MockRes();

    var spy = t.stubOnce(http_https, 'request', function(uri, cb) { cb(mockRes); return mockReq });

    if (ms === undefined) setImmediate(function(){ mockRes.emit('end') });
    else if (ms > 0) setTimeout(function(){ mockRes.emit('end') }, ms);

    spy._mockReq = mockReq;
    spy._mockRes = mockRes;
    return spy;
}

function decode_base64url( str ) {
    return new Buffer(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
}
