google-custom-metrics
=====================

Upload legacy Stackdriver custom metrics to Google Stackdriver.

If you don't know what this means, you probably don't need this package.  If you do,
this is a small HTTP library to upload arbitrary, application-defined metrics
previously sent to Stackdriver to the new Stackdriver.  Stats can be created on the
fly, they just show up in the dashboard like they used to.

Limitations
-----------

- by default, stats are tagged with instance_name but not instance_id
- 


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

Options can be omitted, or be an object with the instance_name to identify samples,
or the object returned from `getPlatformDetails()` that includes information used to
tie a metric to the AWS or GCE instance that it was collected on.

### uploadCustomMetricsToGoogleStackdriver( creds, uploadBodies, callback )

Post each upload body to Google monitoring.  `creds` are used to authenticate the requests;
the callback is invoked with any error and the array of responses received from Google.

### getPlatformDetails( [creds] )

Return information about the instance the code is running on.  This information is used
to tie the metrics to the host it was collected on.  Creds are optional; if provided,
the Google Cloud `project_id` will be added to the details.


Change Log
----------

- 0.1.0 - initial version


Todo
----
