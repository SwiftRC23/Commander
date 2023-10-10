from __future__ import annotations
import argparse
import json
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ... import vault_extensions
from ...display import bcolors
from ..pam.router_helper import router_get_connected_gateways
from discovery_common.jobs import Jobs
from discovery_common.infrastructure import Infrastructure
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from discovery_common.jobs import JobItem


class PAMGatewayActionDiscoverJobStatusCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-status-command')
    parser.add_argument('--gateway', '-g', required=False, dest='gateway', action='store',
                        help='Show only discovery jobs from a specific gateway.')
    parser.add_argument('--job-id', '-j', required=False, dest='job_id', action='store',
                        help='Detailed information for a specific discovery job.')
    parser.add_argument('--file', required=False, dest='json_file', action='store',
                        help='Save status to JSON file.')

    def get_parser(self):
        return PAMGatewayActionDiscoverJobStatusCommand.parser

    def job_detail(self, job):
        pass

    @staticmethod
    def print_job_table(jobs, max_gateway_name):

        print("")
        print(f"{bcolors.HEADER}{'Job ID'.ljust(14, ' ')} "
              f"{'Gateway Name'.ljust(max_gateway_name, ' ')} "
              f"{'Gateway UID'.ljust(22, ' ')} "
              f"{'Status'.ljust(12, ' ')} "
              f"{'Resource UID'.ljust(22, ' ')} "
              f"{'Started'.ljust(19, ' ')} "
              f"{'Completed'.ljust(19, ' ')} "
              f"{'Duration'.ljust(19, ' ')} "
              f"{bcolors.ENDC}")

        print(f"{''.ljust(14, '=')} "
              f"{''.ljust(max_gateway_name, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(12, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')}")

        for job in jobs:
            color = ""
            if job['status'] == "COMPLETE":
                color = bcolors.OKGREEN
            elif job['status'] == "RUNNING":
                color = bcolors.OKBLUE
            elif job['status'] == "FAILED":
                color = bcolors.FAIL
            print(f"{color}{job['job_id']} "
                  f"{job['gateway'].ljust(max_gateway_name, ' ')} "
                  f"{job['gateway_uid']} "
                  f"{job['status'].ljust(12, ' ')} "
                  f"{(job.get('resource_uid') or 'NA').ljust(22, ' ')} "
                  f"{(job.get('start_ts_str') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('end_ts_str') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('duration') or 'NA').ljust(19, ' ')} "
                  f"{bcolors.ENDC}")

    @staticmethod
    def print_job_detail(params, jobs, job_id):

        def _h(text):
            return f"{bcolors.HEADER}{text}{bcolors.ENDC}"

        for job in jobs:
            if job_id == job["job_id"]:
                gateway_context = job["gateway_context"]
                if job['status'] == "COMPLETE":
                    color = bcolors.OKGREEN
                elif job['status'] == "RUNNING":
                    color = bcolors.OKBLUE
                else:
                    color = bcolors.FAIL
                status = f"{color}{job['status']}{bcolors.ENDC}"

                print("")
                print(f"{_h('Job ID')}: {job['job_id']}")
                print(f"{_h('Gateway Name')}: {job['gateway']}")
                print(f"{_h('Gateway UID')}: {job['gateway_uid']}")
                print(f"{_h('Configuration UID')}: {gateway_context.configuration_uid}")
                print(f"{_h('Status')}: {status}")
                print(f"{_h('Resource UID')}: {job.get('resource_uid', 'NA')}")
                print(f"{_h('Started')}: {job['start_ts_str']}")
                print(f"{_h('Completed')}: {job.get('end_ts_str')}")
                print(f"{_h('Duration')}: {job.get('duration')}")

                # If it failed, show the error and stacktrace.
                if job['status'] == "FAILED":
                    print("")
                    print(f"{_h('Gateway Error')}:")
                    print(f"{color}{job['error']}{bcolors.ENDC}")
                    print("")
                    print(f"{_h('Gateway Stacktrace')}:")
                    print(f"{color}{job['stacktrace']}{bcolors.ENDC}")
                # If it finished, show information about what was discovered.
                elif job.get('end_ts') is not None:
                    job_item = job.get("job_item")   # type: JobItem
                    infra = Infrastructure(record=gateway_context.configuration, params=params)
                    infra.load(sync_point=job_item.sync_point)



    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        gateway_filter = kwargs.get("gateway")
        job_id = kwargs.get("job_id")

        # Get all the PAM configuration records
        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))

        # This is used to format the table. Start with a length of 12 characters for the gateway.
        max_gateway_name = 12

        all_jobs = []

        # For each configuration/ gateway, we are going to get all jobs.
        # We are going to query the gateway for any updated status.
        for configuration_record in configuration_records:

            gateway_context = GatewayContext.from_configuration_uid(params, configuration_record.record_uid)
            if gateway_context is None:
                continue

            # If we are using a gateway filter, and this gateway is not the one, then go onto the next conf/gateway.
            if gateway_filter is not None and gateway_context.is_gateway(gateway_filter) is False:
                continue

            # If the gateway name is longer that the prior, set the max length to this gateway's name.
            if len(gateway_context.gateway_name) > max_gateway_name:
                max_gateway_name = len(gateway_context.gateway_name)

            jobs = Jobs(record=configuration_record, params=params)
            for job_item in reversed(jobs.unprocessed_jobs):
                job = job_item.model_dump()
                job["status"] = "RUNNING"
                if job_item.start_ts is not None:
                    job["start_ts_str"] = job_item.start_ts_str
                if job_item.end_ts is not None:
                    job["end_ts_str"] = job_item.end_ts_str
                    job["duration"] = str(job_item.duration_sec)
                    job["status"] = "COMPLETE"

                job["gateway"] = gateway_context.gateway_name
                job["gateway_uid"] = gateway_context.gateway_uid

                # This is needs for details
                job["gateway_context"] = gateway_context
                job["job_item"] = job_item

                if job_item.success is False:
                    job["status"] = "FAILED"

                all_jobs.append(job)

        # Instead of printing a table, save a json file.
        if kwargs.get("json_file") is not None:
            with open(kwargs.get("json_file"), "w") as fh:
                fh.write(json.dumps(all_jobs, indent=4))
                fh.close()
            return

        if len(all_jobs) == 0:
            print(f"{ bcolors.FAIL}There are no discovery jobs. Use 'pam action discover start' to start a "
                  f"discovery job.{bcolors.ENDC}")
            return

        if job_id is not None:
            self.print_job_detail(params, all_jobs, job_id)
        else:
            self.print_job_table(all_jobs, max_gateway_name)
