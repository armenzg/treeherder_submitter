# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Original source(s):
# https://github.com/mozilla/mozmill-ci/blob/master/jenkins-master/jobs/scripts/workspace/submission.py
# https://github.com/rwood-moz/post-to-treeherder/blob/master/post-to-treeherder.py

# Standard libraries
import datetime
import logging
import json
import pprint
import socket
import time
import uuid

from urlparse import urljoin

# Third party modules
from thclient import TreeherderClient, TreeherderJob, TreeherderJobCollection
from mozinfo import info as pf_info

LOG = logging.getLogger(__name__)
RESULTSET_FRAGMENT = 'api/project/{repository}/resultset/?revision={revision}'
JOB_FRAGMENT = '/#/jobs?repo={repository}&revision={revision}'
OPTION_COLLECTION_VALUES = ['opt', 'debug']  # XXX: add missing valid values


def timestamp_now():
    return int(time.mktime(datetime.datetime.now().timetuple()))


class TreeherderSubmitterError(Exception):
    pass


class JobState(object):
    COMPLETED = 'completed'
    PENDING = 'pending'
    RUNNING = 'running'
    VALID_STATES = (COMPLETED, PENDING, RUNNING)


class JobEndResult(object):
    SUCCESS = 'success'
    FAIL = 'busted'
    EXCEPTION = 'exception'
    CANCELED = 'usercancel'
    VALID_RESULTS = (SUCCESS, FAIL, EXCEPTION, CANCELED)


class TreeherderJobFactory(object):
    def __init__(self, submitter):
        self.submitter = submitter
        self.state = None

    def create_job(self, repository, revision, add_platform_info=True,
                   **kwargs):
        ''' This creates a Treeherder job which won't be scheduled.

        Times of the job won't be established here but upon submission.
        The state of the job not established in here.

        XXX: change this code to change anything that is not mandatory as
             optional.
        '''
        job = TreeherderJob()

        if add_platform_info:
            # The middle value in the tuple is mapped using this:
            # https://github.com/mozilla/treeherder/blob/master/ui/js/values.js
            if kwargs.get('platform_info'):
                platform_info = kwargs.get('platform_info')
                # e.g. ('linux', 'linux64', 'x86_64')
                assert type(platform_info) == tuple and len(platform_info) == 3
                platform = platform_info
            else:
                # This information is used to determine under which platform to
                # place your job on the UI
                platform = self._get_treeherder_platform()

            job.add_build_info(*platform)
            job.add_machine_info(*platform)

        job.add_machine(kwargs.get('machine', socket.getfqdn()))

        # If no group_name and group_symbol are specified we default unknown/?
        # which will make the job not to belong to any group
        job.add_group_name(kwargs.get('group_name', 'unknown'))
        job.add_group_symbol(kwargs.get('group_symbol', '?'))
        job.add_job_guid(str(uuid.uuid4()))
        # Bug 1174973 - How can we guarantee unique job names even on different groups?
        job.add_job_name(kwargs['job_name'])
        job.add_job_symbol(kwargs['job_symbol'])
        job.add_option_collection(self._option_collection(kwargs['option_collection']))
        job.add_product_name(kwargs.get('product_name', 'no product'))
        job.add_project(repository)
        job.add_revision(revision)
        job.add_tier(kwargs.get('tier', '1'))

        return job

    def submit_pending(self, job, **kwargs):
        if not self.state:
            self.state = JobState.PENDING
        else:
            raise TreeherderSubmitterError("You can't submit a job with state as as pending.")

        # submit and start times can be the same
        job.add_submit_timestamp(kwargs.get('submit_time', timestamp_now()))
        job.add_start_timestamp(kwargs.get('start_time', timestamp_now()))
        # Bug 1175559 - Workaround for HTTP Error
        job.add_end_timestamp(0)

        self.submitter._submit(job=job, state=self.state)

    def submit_running(self, job, **kwargs):
        if not self.state or self.state == JobState.PENDING:
            # We don't need to be on a pending state before going straight to running
            self.state = JobState.RUNNING
        else:
            raise TreeherderSubmitterError("You can't submit a job with state as as pending.")

        # submit time and start time can be the same
        job.add_submit_timestamp(kwargs.get('submit_time', timestamp_now()))
        job.add_start_timestamp(kwargs.get('start_time', timestamp_now()))
        # Bug 1175559 - Workaround for HTTP Error

        job.add_end_timestamp(0)
        self.submitter._submit(job=job, state=self.state, **kwargs)

    def submit_completed(self, job, result, **kwargs):
        if not self.state or self.state == JobState.RUNNING:
            # We don't need to be on a pending state before going straight to running
            self.state = JobState.COMPLETED
        else:
            raise TreeherderSubmitterError("You can't submit a job with state as as pending.")

        job.add_end_timestamp(kwargs.get('end_time', timestamp_now()))

        self.submitter._submit(job=job, state=self.state, result=result, **kwargs)

    def _option_collection(self, option_collection):
        assert option_collection in OPTION_COLLECTION_VALUES
        # XXX: finish this up
        if option_collection == 'opt':
            return {'opt': True}

    def _get_treeherder_platform(self):
        ''' Return a tuple with platform information for Linux, Mac and Windows for Treeherder.'''
        platform = None  # XXX: Is None a valid value to pass to Treeherder?

        if pf_info['os'] == 'linux':
            platform = ('linux', '%s%s' % (pf_info['os'], pf_info['bits']), '%s' % pf_info['processor'])

        elif pf_info['os'] == 'mac':
            platform = ('mac', 'osx-%s' % pf_info['os_version'].replace('.', '-'), pf_info['processor'])

        elif pf_info['os'] == 'win':
            versions = {'5.1': 'xp', '6.1': '7', '6.2': '8'}
            bits = ('-%s' % pf_info['bits']) if pf_info['os_version'] != '5.1' else ''
            platform = ('win', 'windows%s%s' % (versions[pf_info['os_version']], '%s' % bits),
                        pf_info['processor'],
                        )

        return platform


class TreeherderSubmitter(object):
    ''' This class helps you submit jobs to a specific repository and revision.'''

    def __init__(self, host, protocol='http', treeherder_client_id=None,
                 treeherder_secret=None, dry_run=False, **kwargs):
        self.url = '{}://{}'.format(protocol, host)

        if not dry_run and (not treeherder_client_id or not treeherder_secret):
            raise ValueError('The client_id and secret for Treeherder must be set.')

        self.dry_run = dry_run

        self.client = TreeherderClient(
            server_url=self.url,
            client_id=treeherder_client_id,
            secret=treeherder_secret
        )

    def _submit(self, job, state, **kwargs):
        assert state in JobState.VALID_STATES
        job.add_state(state)

        if state == JobState.COMPLETED:
            job = self._process_completed_request(
                job=job,
                result=kwargs['result'],
                endtime=kwargs.get('endtime', timestamp_now()),
                artifacts=kwargs.get('artifacts', []),
                log_references=kwargs['log_references'],
                job_info_details_panel=kwargs.get('job_info_details_panel', []),
            )

        job_collection = TreeherderJobCollection()
        job_collection.add(job)
        LOG.debug(str(json.dumps(job_collection.to_json())))

        if self.dry_run:
            LOG.info('Dry run; we did not submit any jobs')
        else:
            self.client.post_collection(job.data['project'], job_collection)

            LOG.info('Results are available to view at: {}'.format(
                urljoin(self.url, JOB_FRAGMENT.format(
                    repository=job.data['project'],
                    revision=job.data['revision']))))

    def _process_completed_request(self, job, result, endtime, log_references, artifacts=[],
                                   job_info_details_panel=[]):
        """Update the status of a job to completed.
        """
        assert result in JobEndResult.VALID_RESULTS

        job.add_result(result)
        job.add_end_timestamp(endtime)

        for log in log_references:
            # It expects 'url', 'name' and optionally 'parse_status'
            #
            # If 'parse_status' is 'pending' then Treeherder will not turn the "log viewer" button
            # into a hyperlink, however, you can still use the "raw log" button beside it
            # The 'Failure summary' will show this message:
            #   Log parsing in progress. The raw log is available. This panel will
            #   automatically recheck every 5 seconds.
            #
            # XXX: Determine valid values for 'name'
            # XXX: Should I fail if 'buildbot_text'? 'buildbot_text' requires uploading
            #      a 'text_log_artifact' IIUC
            # https://github.com/mozilla/treeherder/blob/master/treeherder/model/derived/jobs.py#L1604
            job.add_log_reference(**log)

        # We can only submit job info once, so it has to be done when the job completes
        if job_info_details_panel:
            # 1) Generate list with data structure
            job_details = []
            for detail in job_info_details_panel:
                # XXX: We should verify the content_type values
                job_details.append({
                    'content_type': detail['content_type'],
                    'title': detail['title'],
                    'url': detail['url'],
                    'value': detail['value'],
                })

            # 2) Append the special "Job Info" artifact
            # This will show on TH's UI as 'Job details' pane
            artifacts.append({
                'blob': {'job_details': job_details},
                'name': 'Job Info',
                'type': 'json',
            })

        # I think artifacts are stored in the backed without showing up in the UI
        # If you want the artifact to show up, mention it on job_info_details_panel
        for a in artifacts:
            job.add_artifact(
                name=a['name'],
                artifact_type=a['type'],
                blob=a['blob']
            )

        return job
