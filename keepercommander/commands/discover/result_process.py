from __future__ import annotations
import logging
import argparse
import json
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.router_helper import router_get_connected_gateways, router_set_record_rotation_information
from ... import api, subfolder, utils, crypto, vault, vault_extensions
from ...display import bcolors
from ...proto import router_pb2, record_pb2
from ...loginv3 import CommonHelperMethods
from discovery_common.jobs import Jobs
from discovery_common.process import Process
from discovery_common.rule import Rules
from discovery_common.types import (RuleActionEnum, DiscoveryObject, BulkRecordAdd, BulkRecordFail, PromptResult,
                                    PromptActionEnum)
from typing import Optional, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import TypedRecord
    from keeper_dag.vertex import DAGVertex
    from discovery_common.types import UserAcl


class QuitException(Exception):
    pass


class PAMGatewayActionDiscoverResultProcessCommand(PAMGatewayActionDiscoverCommandBase):

    """
    Process the discovery data


    """
    parser = argparse.ArgumentParser(prog='dr-discover-command-process')
    parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                        help='Discovery job id.')
    parser.add_argument('--dry-run', required=False, dest='dry_run', action='store_true',
                        help='Do not add records.')
    parser.add_argument('--add-all', required=False, dest='add_all', action='store_true',
                        help='Add record when prompted.')

    def get_parser(self):
        return PAMGatewayActionDiscoverResultProcessCommand.parser

    @staticmethod
    def _get_shared_folder(params: KeeperParams, pad: str, gateway_context: GatewayContext) -> str:
        while True:
            shared_folders = gateway_context.get_shared_folders(params)
            index = 0
            for folder in shared_folders:
                print(f"{pad}* {bcolors.HEADER}{index+1}{bcolors.ENDC} - {folder.get('uid')}  {folder.get('name')}")
                index += 1
            selected = input(f"{pad}Enter number of the shared folder>")
            try:
                return shared_folders[int(selected) - 1].get("uid")
            except ValueError:
                print(f"{pad}{bcolors.FAIL}Input was not a number.{bcolors.ENDC}")

    @staticmethod
    def get_field_values(record: TypedRecord, field_type: str) -> List[str]:
        return next(
            (f.value
             for f in record.fields
             if f.type == field_type),
            None
        )

    def get_keys_by_record(self, params: KeeperParams, gateway_context: GatewayContext,
                           record: TypedRecord) -> List[str]:
        """
        For the record, get the values of fields that are key for this record type.

        :param params:
        :param gateway_context:
        :param record:
        :return:
        """

        key_field = Process.get_key_field(record.record_type)
        keys = []
        if key_field == "host_port":
            values = self.get_field_values(record, "pamHostname")
            if len(values) == 0:
                return []

            host = values[0].get("hostName")
            port = values[0].get("port")
            if port is not None:
                if host is not None:
                    keys.append(f"{host}:{port}".lower())

        elif key_field == "host":
            values = self.get_field_values(record, "pamHostname")
            if len(values) == 0:
                return []

            host = values[0].get("hostName")
            if host is not None:
                keys.append(host.lower())

        elif key_field == "user":

            # This is user protobuf values.
            # We could make this also use record linking if we stop using protobuf.

            record_rotation = params.record_rotation_cache.get(record.record_uid)
            if record_rotation is not None:
                controller_uid = record_rotation.get("configuration_uid")
                if controller_uid is None or controller_uid != gateway_context.configuration_uid:
                    return []

                resource_uid = record_rotation.get("resource_uid")
                # If the resource uid is None, the Admin Cred Record has not been set.
                if resource_uid is None:
                    return []

                values = self.get_field_values(record, "login")
                if len(values) == 0:
                    return []

                keys.append(f"{resource_uid}:{values[0]}".lower())

        return keys

    def _build_record_cache(self, params: KeeperParams, gateway_context: GatewayContext) -> dict:

        """
        Make a lookup cache for all the records.

        This is used to flag discovered items as existing if the record has already been added. This is used to
        prevent duplicate records being added.
        """

        logging.debug(f"building the PAM record cache")

        # Make a cache of existing record by the criteria per record type
        cache = {
            "pamUser": {},
            "pamMachine": {},
            "pamDirectory": {},
            "pamDatabase": {}
        }

        # Set all the PAM Records
        records = list(vault_extensions.find_records(params, "pam*"))
        for record in records:
            # If the record type is not part of the cache, skip the record
            if record.record_type not in cache:
                continue

            # Load the full record
            record = vault.TypedRecord.load(params, record.record_uid)  # type: Optional[TypedRecord]

            cache_keys = self.get_keys_by_record(
                params=params,
                gateway_context=gateway_context,
                record=record
            )
            if len(cache_keys) == 0:
                continue

            for cache_key in cache_keys:
                cache[record.record_type][cache_key] = record.record_uid

        return cache

    def _edit_record(self, content: DiscoveryObject, pad: str, editable: List[str]) -> bool:

        edit_label = input(f"{pad}Enter 'title' or the name of the {bcolors.OKGREEN}Label{bcolors.ENDC} to edit, "
                           "RETURN to cancel> ")

        # Just pressing return exits the edit
        if edit_label == "":
            return False

        # If the "title" is entered, then edit the title of the record.
        if edit_label.lower() == "title":
            new_title = input(f"{pad}Enter new title> ")
            content.title = new_title

        # If a field label is entered, and it's in the list of editable fields, then allow the user to edit.
        elif edit_label in editable:
            new_value = None
            if edit_label in self.FIELD_MAPPING:
                type_hint = self.FIELD_MAPPING[edit_label].get("type")
                if type_hint == "dict":
                    field_input_format = self.FIELD_MAPPING[edit_label].get("field_input")
                    new_value = {}
                    for field in field_input_format:
                        new_value[field.get('key')] = input(f"{pad}Enter {field_input_format.get('prompt')} value> ")
                elif type_hint == "multiline":
                    new_value = input(f"{pad}Enter {edit_label} value> ")
                    new_values = map(str.strip, new_value.split(','))
                    new_value = "\n".join(new_values)
            else:
                new_value = input(f"{pad}Enter new value> ")

            for edit_field in content.fields:
                if edit_field['label'] == edit_label:
                    edit_field['value'] = [new_value]

        # Else, the label they entered cannot be edited.
        else:
            print(
                f"{pad}{bcolors.FAIL}The field is not editable.{bcolors.ENDC}")
            return False

        return True

    @staticmethod
    def _ignore_record(params: KeeperParams, content: DiscoveryObject, gateway_context: GatewayContext) -> bool:

        content.ignore_object = True

        action_rule_item = Rules.make_action_rule_from_content(
            content=content,
            action=RuleActionEnum.IGNORE
        )

        # Add a rule to ignore this object when doing future discovery.
        rules = Rules(record=gateway_context.configuration, params=params)
        rules.add_rule(action_rule_item)

        return True

    def _show_description(self, vertex: DAGVertex) -> bool:
        content = Process.get_discovery_object(vertex)
        if content.record_exists is False:
            return True
        else:
            for next_vertex in vertex.has_vertices():
                if self._show_description(next_vertex) is True:
                    return True
        return False

    def _prompt_display_fields(self, content: DiscoveryObject, pad: str) -> List[str]:

        editable = []
        for field in content.fields:
            has_editable = False
            if field.label in ["login", "password", "distinguishedName", "alternativeIPs", "database"]:
                editable.append(field.label)
                has_editable = True
            value = field.value
            if len(value) > 0:
                value = value[0]
                if field.label in self.FIELD_MAPPING:
                    type_hint = self.FIELD_MAPPING[field.label].get("type")
                    formatted_value = []
                    if type_hint == "dict":
                        field_input_format = self.FIELD_MAPPING[field.label].get("field_format")
                        for format_field in field_input_format:
                            formatted_value.append(f"{format_field.get('label')}: "
                                                   f"{value.get(format_field.get('key'))}")
                    elif type_hint == "multiline":
                        formatted_value.append(", ".join(value.split("\n")))
                    value = ", ".join(formatted_value)
            else:
                if has_editable is True:
                    value = f"{bcolors.FAIL}MISSING{bcolors.ENDC}"
                else:
                    value = f"{bcolors.OKBLUE}None{bcolors.ENDC}"

            color = bcolors.HEADER
            if has_editable is True:
                color = bcolors.OKGREEN

            print(f"{pad}  "
                  f"{color}Label:{bcolors.ENDC} {field.label}, "
                  f"{bcolors.HEADER}Type:{bcolors.ENDC} {field.type}, "
                  f"{bcolors.HEADER}Value:{bcolors.ENDC} {value}")

        if len(content.notes) > 0:
            print("")
            for note in content.notes:
                print(f"{pad}* {note}")

        print("")

        return editable

    def _prompt(self, vertex: DAGVertex, parent_vertex: DAGVertex, content: DiscoveryObject, acl: UserAcl,
                indent: int = 0, context: Optional[Any] = None) -> PromptResult:

        if context is None:
            raise Exception("Context not set for processing the discovery results")

        params = context.get("params")
        gateway_context = context.get("gateway_context")
        dry_run = context.get("dry_run")
        auto_add = context.get("auto_add")

        pad = ""
        if indent > 0:
            pad = "".ljust(2 * indent, ' ')

        if self._show_description(vertex) is True:
            print(f"{pad}{bcolors.HEADER}{content.description}{bcolors.ENDC}")

        show_current_object = True
        while show_current_object is True:
            print(f"{pad}{bcolors.HEADER}Record Title:{bcolors.ENDC} {content.title}")

            logging.debug(f"Fields: {content.fields}")

            # Display the fields and return a list of fields are editable.
            editable = self._prompt_display_fields(content=content, pad=pad)

            while True:

                shared_folder_uid = content.shared_folder_uid
                if shared_folder_uid is None:
                    shared_folder_uid = gateway_context.default_shared_folder_uid

                count_prompt = f"{bcolors.HEADER}[]{bcolors.ENDC}"
                edit_add_prompt = f"{count_prompt} (E)dit, (A)dd, "
                if dry_run is True:
                    edit_add_prompt = ""
                shared_folders = gateway_context.get_shared_folders(params)
                if len(shared_folders) > 1 and dry_run is False:
                    folder_name = next((x['name']
                                        for x in shared_folders
                                        if x['uid'] == shared_folder_uid),
                                       None)
                    edit_add_prompt = f"{count_prompt} (E)dit, (A)dd to {folder_name}, Add to (F)older, "
                prompt = f"{edit_add_prompt}(S)kip, (I)gnore, (Q)uit"

                command = "a"
                if auto_add is False:
                    command = input(f"{pad}{prompt}> ").lower()
                if (command == "a" or command == "f") and dry_run is False:

                    print(f"{pad}{bcolors.OKGREEN}Adding record to save queue.{bcolors.ENDC}")
                    print("")

                    if command == "f":
                        shared_folder_uid = self._get_shared_folder(params, pad, gateway_context)

                    # If we have an ACL, set that this object (user) belongs to this resource.
                    if acl is not None:
                        acl.belongs_to = True

                    content.shared_folder_uid = shared_folder_uid

                    return PromptResult(
                        action=PromptActionEnum.ADD,
                        acl=acl,
                        content=content
                    )

                elif command == "e" and dry_run is False:
                    self._edit_record(content, pad, editable)
                    break

                elif command == "i":
                    # TODO - Add ignore list
                    if self._ignore_record(params, content, gateway_context) is False:
                        print(f"{pad}{bcolors.FAIL}The router require returned a failure{bcolors.ENDC}")

                    return PromptResult(action=PromptActionEnum.IGNORE)

                elif command == "s":
                    print(f"{pad}{bcolors.OKBLUE}Skipping record{bcolors.ENDC}")

                    return PromptResult(action=PromptActionEnum.SKIP)
                elif command == "q":
                    raise QuitException()
            print()

    @staticmethod
    def _prepare_record(content: DiscoveryObject, context: Optional[Any] = None) -> (Any, str):

        """
        Prepare the Vault record side.

        It's not created here.
        It will be created at the end of the processing run in bulk.
        We to build a record to get a record UID.

        :params content: The discovery object instance.
        :params context: Optionally, it will contain information set from the run() method.
        :returns: Returns an unsaved Keeper record instance.
        """

        if context is None:
            raise Exception("Context not set for processing the discovery results")

        params = context.get("params")

        # Create an instance of a vault record to structure the data
        record = vault.TypedRecord()
        record.type_name = content.record_type
        record.record_uid = utils.generate_uid()
        record.record_key = utils.generate_aes_key()
        record.title = content.title
        for field in content.fields:
            field_args = {
                "field_type": field.type,
                "field_value": field.value
            }
            if field.type != field.label:
                field_args["field_label"] = field.label
            record_field = vault.TypedField.new_field(**field_args)
            record_field.required = field.required
            record.fields.append(record_field)

        folder = params.folder_cache.get(content.shared_folder_uid)
        folder_key = None  # type: Optional[bytes]
        if isinstance(folder, subfolder.SharedFolderFolderNode):
            shared_folder_uid = folder.shared_folder_uid
        elif isinstance(folder, subfolder.SharedFolderNode):
            shared_folder_uid = folder.uid
        else:
            shared_folder_uid = None
        if shared_folder_uid and shared_folder_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache.get(shared_folder_uid)
            folder_key = shared_folder.get('shared_folder_key_unencrypted')

        record_add_protobuf = record_pb2.RecordAdd()
        record_add_protobuf.record_uid = utils.base64_url_decode(record.record_uid)
        record_add_protobuf.record_key = crypto.encrypt_aes_v2(record.record_key, params.data_key)
        record_add_protobuf.client_modified_time = utils.current_milli_time()
        record_add_protobuf.folder_type = record_pb2.user_folder
        if folder:
            record_add_protobuf.folder_uid = utils.base64_url_decode(folder.uid)
            if folder.type == 'shared_folder':
                record_add_protobuf.folder_type = record_pb2.shared_folder
            elif folder.type == 'shared_folder_folder':
                record_add_protobuf.folder_type = record_pb2.shared_folder_folder
            if folder_key:
                record_add_protobuf.folder_key = crypto.encrypt_aes_v2(record.record_key, folder_key)

        data = vault_extensions.extract_typed_record_data(record)
        json_data = api.get_record_data_json_bytes(data)
        record_add_protobuf.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        # refs = vault_extensions.extract_typed_record_refs(record)
        # for ref in refs:
        #     ref_record_key = None  # type: Optional[bytes]
        #     if record.linked_keys:
        #         ref_record_key = record.linked_keys.get(ref)
        #     if not ref_record_key:
        #         ref_record = vault.KeeperRecord.load(params, ref)
        #         if ref_record:
        #             ref_record_key = ref_record.record_key
        #
        #     if ref_record_key:
        #         link = record_pb2.RecordLink()
        #         link.record_uid = utils.base64_url_decode(ref)
        #         link.record_key = crypto.encrypt_aes_v2(ref_record_key, record.record_key)
        #         add_record.record_links.append(link)

        if params.enterprise_ec_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                record_add_protobuf.audit.version = 0
                record_add_protobuf.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

        return record_add_protobuf, record.record_uid

    @classmethod
    def _create_records(cls, records: List[BulkRecordAdd], context: Optional[Any] = None) -> List[BulkRecordFail]:

        if context is None:
            raise Exception("Context not set for processing the discovery results")

        params = context.get("params")
        gateway_context = context.get("gateway_context")

        # STEP 1 - Batch add new records

        # Generate a list of RecordAdd instance.
        # In BulkRecordAdd they will be the record instance.
        record_add_list = [r.record for r in records]  # type: List[record_pb2.RecordAdd]

        records_per_request = 999

        add_results = []  # type: List[record_pb2.RecordModifyResult]
        logging.debug("adding record in batches")
        while record_add_list:
            logging.debug(f"* adding batch")
            rq = record_pb2.RecordsAddRequest()
            rq.client_time = utils.current_milli_time()
            rq.records.extend(record_add_list[:records_per_request])
            record_add_list = record_add_list[records_per_request:]
            rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
            add_results.extend(rs.records)

        if len(add_results) != len(records):
            logging.debug(f"attempted to batch add {len(records)} record(s), "
                          f"only have {len(add_results)} results.")

        # STEP 3 - Add rotation settings.
        # Use the list we passed in, find the results, and add if the additions were successful.

        failures = []  # type: List[BulkRecordFail]

        for record in records:
            add_record = record.record
            title = record.title

            # Find the result for this record.
            result = next(
                (x
                 for x in add_results
                 if add_record.record_uid == CommonHelperMethods.bytes_to_url_safe_str(x.record_uid)
                 ), None)

            # If we didn't get a result, then don't add the rotation settings.
            if result is None:
                failures.append(
                    BulkRecordFail(
                        title=title,
                        error="No status on addition to Vault. Cannot determine if added or not."
                    )
                )
                logging.debug(f"Did not get a result when adding record {title}")
                continue

            # Check if addition failed. If it did fail, don't add the rotation settings.
            success = (result.status == record_pb2.RecordModifyResult.DESCRIPTOR.values_by_name['RS_SUCCESS'].number)
            status = record_pb2.RecordModifyResult.DESCRIPTOR.values_by_number[result.status].name
            if success is False:
                failures.append(
                    BulkRecordFail(
                        title=title,
                        error=status
                    )
                )
                logging.debug(f"Had problem adding record for {title}: {status}")
                continue

            rq = router_pb2.RouterRecordRotationRequest()
            rq.recordUid = url_safe_str_to_bytes(add_record.record_uid)
            rq.revision = 0

            # Set the gateway/configuration that this record should be connected.
            rq.configurationUid = url_safe_str_to_bytes(gateway_context.configuration_uid)

            # Only set the resource if the record type is a PAM User.
            # Machines, databases, and directories have a login/password in the record that indicates who the admin is.
            if add_record.record_type == "pamUser":
                # Get the parent UID.
                # When it was added to add_record_queue, we may have not known
                # the parent's record UID.
                # We should know now.
                parent_uid = add_record.dag.parent.content.get("keeper_record_uid")
                if parent_uid is not None:
                    rq.resourceUid = url_safe_str_to_bytes(parent_uid)

            # Right now, the schedule and password complexity are not set. This would be part of a rule engine.
            rq.schedule = ''
            rq.pwdComplexity = b''

            router_set_record_rotation_information(params, rq)

            # If we got here, update the DAG item with
            add_record.dag.update()

        params.sync_data = True

        return failures

    def execute(self, params: KeeperParams, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        job_id = kwargs.get("job_id")
        dry_run = kwargs.get("dry_run", False)
        auto_add = kwargs.get("auto_add", False)

        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        for configuration_record in configuration_records:

            gateway_context = GatewayContext.from_configuration_uid(params, configuration_record.record_uid)
            if gateway_context is None:
                continue

            record_cache = self._build_record_cache(
                params=params,
                gateway_context=gateway_context
            )

            # Get the job
            # This will give us the sync point for the delta
            jobs = Jobs(record=configuration_record, params=params)
            job_item = jobs.get_job(job_id)
            if job_item is None:
                continue

            if job_item.end_ts is None:
                print(f'{bcolors.FAIL}Discovery job is currently running. Cannot process.{bcolors.ENDC}')
                return
            if job_item.success is False:
                print(f'{bcolors.FAIL}Discovery job failed. Cannot process.{bcolors.ENDC}')
                return

            process = Process(record=configuration_record, job_id=job_id, params=params)

            if dry_run is True:
                if auto_add is True:
                    logging.debug("dry run has been set, disable auto add.")
                    auto_add = False

                print(f"{bcolors.HEADER}The DRY RUN flag has been set. The rule engine will not add any records. "
                      f"You will not be prompted to edit or add records.{bcolors.ENDC}")
                print("")

            if auto_add is True:
                print(f"{bcolors.HEADER}The AUTO ADD flag has been set. All found items will be added.{bcolors.ENDC}")
                print("")

            try:
                failures = process.run(
                    prompt_func=self._prompt,
                    record_prepare_func=self._prepare_record,
                    record_create_func=self._create_records,
                    record_cache=record_cache,
                    context={
                        "params": params,
                        "gateway_context": gateway_context,
                        "dry_run": dry_run,
                        "auto_add": auto_add
                    }
                )

                #     success_count = len(add_record_queue) - len(failures)
                #     print("")
                #     print(f"{bcolors.OKGREEN}Added {success_count} "
                #           f"record{'s' if success_count != 1 else ''}.{bcolors.ENDC}")
                #     if len(failures) > 0:
                #         print(f"{bcolors.FAIL}There was {len(failures)} "
                #               f"failure{'s' if len(failures) != 1 else ''}.{bcolors.ENDC}")
                #         for fail in failures:
                #             print(f" * {fail.get('title')}: {fail.get('status')}")

            except QuitException:
                # Not an error, just a quick way of getting out of a recursion.
                logging.debug("quit")

            # elif self.anything_to_add(summary) is False:
            #    print(f"{bcolors.OKGREEN}All items have been added for this discovery job.{bcolors.ENDC}")
            #
            # else:
            #     print(f"{bcolors.FAIL}No records have been added.{bcolors.ENDC}")

            return

        print(f"{bcolors.HEADER}Could not find the Discovery job.{bcolors.ENDC}")
        print("")
