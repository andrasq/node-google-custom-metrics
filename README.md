google-custom-metrics
=====================
[![Build Status](https://api.travis-ci.org/andrasq/node-google-custom-metrics.svg?branch=master)](https://travis-ci.org/andrasq/node-google-custom-metrics?branch=master)
[![Coverage Status](https://codecov.io/github/andrasq/node-google-custom-metrics/coverage.svg?branch=master)](https://codecov.io/github/andrasq/node-google-custom-metrics?branch=master)


Upload legacy Stackdriver custom metrics to Google Stackdriver.

If you don't know what this means, you probably don't need this package.  If you do,
this is a small library to send via HTTP arbitrary, application-defined metrics
previously sent to Stackdriver to the new Stackdriver.  Stats can be created on the
fly, they just show up in the dashboard like they used to.

The code is designed to be easy to drop into any existing code: given `body`, a legacy
stackdriver custom metrics upload object, and `creds`, the GCP service account
credentials object, upload the custom metrics to Google Stackdriver with:

    var gm = require('google-custom-metrics');

    var body = getLegacyStackdriverUploadObject();
    var creds = getGoogleServiceAccountCredentialsObject();

    var hostInfo = gm.getPlatformDetails(creds);
    var batches = gm.convertStackdriverUploadToGoogleStackdriver(hostInfo, body);
    gm.uploadCustomMetricsToGoogleStackdriver(creds, batches, function(err, replies) {
        // replies is an array
    })


Specifics
---------

- without platform details, stats are tagged with just `instance_name` and
  the resource labels will be empty
- metrics can be created on the fly as custom metrics
- convention is to also check `process.env.GOOGLE_APPLICATIONS_CREDENTIALS`
  for the google monitoring service account credentials


Api
---

### convertStackdriverUploadToGoogleStackdriver( [options,] postBody )

Convert a legacy Stackdriver metrics upload into an array of Google Stackdriver uploads.
Each upload the the complete POST request object that will be serialized and sent.

`postBody` is the object that would be serialized and sent to Stackdriver, in the form

    { timestamp: 123456789,
      proto_version: 1,
      data: [
        { name: 'stat-name',
          value: 1234.5,
          collected_at: 123456789,
          instance: 'i-0001' },
        ...
      ]

Options can be omitted, or be an object with the `instance_name` to identify samples,
or the object returned from `getPlatformDetails()` that includes information used to
tie a metric to the AWS or GCE instance that it was collected on.  The default instance
name is the `hostname -s`.

The response will be an array of Google Stackdriver POST bodies, something like
(for 'global' type un-associated metrics, the `resource.labels` attributes would
be empty, and `resource.type` would be 'global'):

    {
      timeSeries: [
        {
          metric: {
            type: 'custom.googleapis.com/stat-name',
            labels: {
              instance_name: options.instance_name,
            }
          },
          resource: {
            type: 'aws_ec2_instance',
            labels: {
              instance_id: 'i-0123abcd',
              instance_name: 'my-aws-vm-host',
              aws_account: 'my-account-id',
              region: 'aws:us-east-1',
            }
          },
          points: [
            {
              interval: {
                endTime: '2017-12-01T12:34:56.789Z',
              },
              value: {
                doubleValue: 1234.5
              }
            }
          ]
        }
      ]
    }

### uploadCustomMetricsToGoogleStackdriver( creds, uploadBodies, callback(err, replies) )

Post each upload body to Google monitoring.  `creds` are used to authenticate the requests;
the callback is invoked with any error and the array of responses received from Google.
Each response contains eg `{ statusCode: 200, body: { ... } }`, the http status code and
the reply body as received from Google.  In case of error, body.error.message will often
contain the error message.

### getPlatformDetails( [creds] [,callerJson] )

Return information about the instance the code is running on.  This information is used
to associate the metrics to the host it was collected on.  Creds are optional; if provided,
the Google Cloud `project_id` will be added to the details included with the custom metrics.
If creds are passed, an optional second parameter may be used to pass the json to parse for
patform information.  The json may be a string, a Buffer, or an already parsed object.

If the platform details are omitted from the converted upload, `'global'` type custom
metrics are uploaded with just the `metrics.labels.instance_name` set to the hostname.


Change Log
----------

- 0.12.1 - update getPlatformDetails docs, make work with node v0.10
- 0.12.0 - work around non-js-compatible GCE platform json, omit the GCE zone path
- 0.11.0 - have `getPlatformDetails()` accept a json bundle to parse for details
- 0.10.1 - split out microreq
- 0.9.0 - initial published version


Todo
----

- pre-combine same-named stats that arrive the same minute, round timestamp to the minute,
  then offset the timestamp by 1 ms every upload for 10000 ms (ie, 10k uploads).
  Should guarantee monotonically increasing timestamps even across upload boundaries,
  and automatically de-dups the upload.
