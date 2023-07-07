import requests, getpass, re
from time import sleep

class Falcon():
    """ A class for interfacing with the Crowdstrike faclon API using Oauth 2 for authentication.
    Session is created at initialization, though is only valid for 30 minutes. 
    """
    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.api_base = "https://api.crowdstrike.com"
        self.session = requests.session()

    def check_response(self,response):
        if response.ok != True:
            raise ValueError(f'{response.status_code} - {response.reason}')

    # these sessions do expire after 30 minutes, but shouldn't matter really
    def new_session(self,client_id, client_secret = None):
        token_api = f'{self.api_base}/oauth2/token'
        if client_secret is None:
            client_secret = getpass.getpass("Please enter your client secret:\n")
        headers = {
            "accept":"application/json"
        }
        body = {
            "client_id":client_id,
            "client_secret":client_secret
        }
        self.session.verify = False
        token_req = self.session.post(token_api,headers={"Content-Type":"application/x-www-form-urlencoded"},data=body)
        self.check_response(token_req)
        headers['Authorization'] = f'Bearer {token_req.json()["access_token"]}'
        headers['Content-Type'] = 'application/json'
        self.session.headers = headers

    def _query_param_builder(self,query=None,filter=None,sort=None,limit=None,offset=None):
        query_params = {
            "q":query,
            "filter":filter,
            "sort":sort,
            "limit":limit,
            "offset":offset
        }
        return {k:v for k,v in query_params.items() if v is not None}

    #names have to be all lowercase even if not in UI
    def group_search(self,query=None,group_filter=None,sort=None,limit=None,offset=None):
        search_params = self._query_param_builder(query,group_filter,sort,limit,offset)
        group_api = f'{self.api_base}/devices/combined/host-groups/v1'
        group = self.session.get(url=group_api,params=search_params)
        self.check_response(group)
        return group

    def device_search(self,query=None,device_filter=None,sort=None,limit=None,offset=None):
        search_params = self._query_param_builder(query,device_filter,sort,limit,offset)
        device_search_api = f'{self.api_base}/devices/queries/devices/v1'
        device = self.session.get(url=device_search_api,params=search_params)
        self.check_response(device)
        return device

    def detection_search(self,query=None,filter=None,sort=None,limit=None,offset=None):
        search_params = self._query_param_builder(query,filter,sort,limit,offset)
        detection_search_api = f'{self.api_base}/detects/queries/detects/v1'
        detection = self.session.get(url=detection_search_api,params=search_params)
        self.check_response(detection)
        return detection

    def incident_search(self,inc_filter):
        valid_filters = [
            "host_ids","name","description","users","tags","fine_score",
            "start","end","assigned_to_name","state","status","modified_timestamp"
        ]
        incident_search_api = f'{self.api_base}/incidents/queries/incidents/v1'
        if inc_filter.split(":")[0] not in valid_filters:
            raise KeyError("Filter doesn't begin with a supported filter operator.")
        results = self.session.get(incident_search_api,params={"filter":inc_filter})
        self.check_response(results)
        return results

    def get_device_id_by_hostname(self,hostname):
        #remove domain if it exists
        host = hostname.split(".")[0]
        search_filter = f'hostname:\'{host}\''
        search = self.device_search(device_filter=search_filter)
        if len(search.json()['resources']) == 0:
            raise ValueError("No devices found by that name. Ensure case and spelling is correct.")
        else: 
            device_ids = search.json()['resources']    
        return device_ids

    def get_detection_ids_by_hostname(self,hostname):
        search_filter = f'hostname:{hostname}'
        detections = self.detection_search(filter=search_filter)
        return detections.json()['resources']

    #must be ldt:<detectionId>:<processId> format for id params
    #max, this accepts 1000 entities
    def get_detection_summary(self,ids):
        summary_api = f'{self.api_base}/detects/entities/summaries/GET/v1'
        if isinstance(ids,list) and len(ids) > 1000:
            summaries = list()
            offset=0
            while offset // 1000 < (len(ids) // 1000):
                offset += 1000
                body = {"ids":ids[(offset-1000):offset]}
                summary = self.session.post(summary_api,json=body)
                self.check_response(summary)
                summaries.append(summary)
            body = {"ids":ids[offset:]}
            summary = self.session.post(summary_api,json=body)
            self.check_response(summary)
            summaries.append(summary)
        else:
            body = {"ids":ids if isinstance(ids,list) else [ids]}
            summary = self.session.post(summary_api,json=body)
            self.check_response(summary)
            summaries = summary
        return summaries

    def update_detection_state(self,ids, assigned_to_email, comment='', status=''):
        update_api = f'{self.api_base}/detects/entities/detects/v2'
        try:
            assigned_to_uuid = self.get_user_uuid(user_email=assigned_to_email)
            body = {
                "assigned_to_uuid":assigned_to_uuid,
                "comment":comment,
                "ids":ids if isinstance(ids,list) else [ids],
                "show_in_ui":True,
                "status":status
            }
        except:
            raise ValueError("email supplied is not a valid user")
        if len(status) >= 1:
            if status not in ['new','in_progress','true_positive','false_positive','ignored']:
                raise ValueError("'status' must be one of the following values: new, in_process, true_positive, false_positive, ignored")
        result = self.session.patch(update_api, json=body)
        self.check_response(result)
        return result

    def update_incident_state(self,ids,action,value):
        incident_api = f'{self.api_base}/incidents/entities/incident-actions/v1'
        possible_actions = ["add_tag","delete_tag","update_name","update_description","update_status"]
        statuses = {"New":"20","Reopened":"25","In Progress":"30","Closed":"40"}
        if action.lower() in possible_actions:
            if action == "update_status":
                try: action_value = statuses[value.title()]
                except KeyError: 
                    raise KeyError("A valid status was not provided. Valid statuses are New, Reopened, In Progress, and Closed.")
            else: action_value = value
        else: 
            raise KeyError("A valid action was not provided. Valid actions are add_tag, delete_tag, update_name, update_description, and update_status")
        body = {
            "action_parameters":[
                {
                    "name":action,
                    "value":action_value
                }
            ],
            "ids":ids if isinstance(ids,list) else [ids]
        }
        results = self.session.post(url=incident_api,json=body)
        self.check_response(results)
        return results

    def get_incident_summary(self,ids):
        incident_summary_api = f'{self.api_base}/incidents/entities/incidents/GET/v1'
        body = {"ids":ids if isinstance(ids,list) else [ids]}
        results = self.session.post(url=incident_summary_api,json=body)
        self.check_response(results)
        return results

    def get_user_uuid(self,user_email):
        user_api = f'{self.api_base}/users/queries/user-uuids-by-email/v1?uid={user_email}'
        user = self.session.get(user_api)
        self.check_response(user)
        return user.json()['resources'][0]

    def contain_host(self,action, **host):
        contaiment_api = f'{self.api_base}/devices/entities/devices-actions/v2'
        if action not in ['contain','lift_containment']:
            raise ValueError(f'{action} is not an acceptable value. Options: contain, lift_containment')
        if 'id' in host:
            device_id = host['device_id']
        elif 'hostname' in host:
            device_id = self.get_device_id_by_hostname(host['hostname'])
        else:
            raise IndexError("'host' param must contain either a 'hostname' key with the system name or 'id' key with the device id")
        body = {"ids":device_id}
        params = {"action_name":action}
        contain = self.session.post(contaiment_api, params=params, json=body)
        self.check_response(contain)
        return contain

    #returns device_id
    def get_device_id_by_ip(self,ip):
        search_filter = f'local_ip:\'{ip}\''
        search = self.device_search(device_filter=search_filter)
        if len(search.json()['resources']) == 0:
            raise ValueError("No devices found by that ip.")
        else:
            device_ids = search.json()['resources']
        return device_ids

    def get_device_details_by_id(self,device_ids):
        device_detail_api = f'{self.api_base}/devices/entities/devices/v2'
        if not isinstance(device_ids,list):
            device_ids = [device_ids]
        search = self.session.post(url=device_detail_api,json={"ids":device_ids})
        self.check_response(search)
        if len(search.json()['resources']) < 1:
            raise ValueError("No devices found by that name. Ensure case and spelling is correct.")
        else: 
            device_details = search.json()['resources']
        return device_details

    def get_device_details_by_ip(self,ip):
        device_ids = self.get_device_id_by_ip(ip)
        return self.get_device_details_by_id(device_ids)

    def get_device_details_by_hostname(self,hostname):
        device_id = self.get_device_id_by_hostname(hostname)
        return self.get_device_details_by_id(device_id)

    def get_device_scroll_ids(self,filter=None,offset=None):
        if offset == None:
            device_scroll_api = "{0}/devices/queries/devices-scroll/v1".format(self.api_base)
        else:
            device_scroll_api = "{0}/devices/queries/devices-scroll/v1?offset={1}".format(self.api_base,offset)
        resp = self.session.get(device_scroll_api,params={"filter":filter})
        host_ids = resp.json()['resources']
        total = resp.json()['meta']['pagination']['total']
        offset = resp.json()['meta']['pagination']['offset']
        return host_ids, total, offset
    
    def get_all_device_ids(self,filter=None):
        all_host_ids, total, offset = self.get_device_scroll_ids(filter=filter)
        count = 0
        while len(all_host_ids) <= total:
            host_ids, total, offset = self.get_device_scroll_ids(filter=filter,offset=offset)
            all_host_ids.extend(host_ids)
            count +=1
        return all_host_ids

    def update_device_tags_by_id(self,device_ids,tags,action):
        device_tag_api = "{0}/devices/entities/devices/tags/v1".format(self.api_base)
        actions = ['add','remove']
        if action not in actions:
            raise ValueError("{0} must be one of the following values: {1}".format(action,",".join(actions)))
        if not isinstance(device_ids,list):
            device_ids=[device_ids]
        if len(device_ids) > 5000:
            raise ValueError("Cannot update more than 5000 devices in a single request, aborting")
        if not isinstance(tags,list):
            tags = [tags]
        body = {
            "device_ids":device_ids,
            "action":"add",
            "tags":["FalconGroupingTags/{0}".format(tag) for tag in tags]
        }
        resp = self.session.patch(device_tag_api,json=body)
        return resp

    def add_device_tags_by_id(self,device_ids,tags):
        return self.update_device_tags_by_id(device_ids,tags,'add')

    def remove_device_tags_by_id(self,device_ids,tags):
        return self.update_device_tags_by_id(device_ids,tags,'remove')

    #names have to be all lowercase even if UI has some upper
    def get_device_group_id(self,name):
        search_filter = f'name:\'{name.lower()}\''
        group = self.group_search(group_filter=search_filter)
        try:
            group_id = group.json()['resources'][0]['id']
        except:
            raise ValueError("No groups found by that name. Ensure spelling is correct")
        return group_id

    #this will break if it receives multiple device ids, no need to build out for now
    def update_device_group(self,group_id,device_id,action):
        if len(device_id) != 1:
            raise IndexError("update_device_group supports taking exactly one device_id at a time.")
        device_update_api = f'{self.api_base}/devices/entities/host-group-actions/v1?action_name={action}'
        if action not in ['add-hosts','remove-hosts']:
            raise ValueError(f'{action} is not a valid action. Acceptable values are add-hosts and remove-hosts.')
        body = {
            'action_parameters':[{
                'name':'filter',
                'value':f'(device_id:{device_id})'
            }],
            'ids':[
                group_id
            ]
        }
        return self.session.post(url=device_update_api,json=body)

    def add_device_to_group_by_name(self,group_name,device_name):
        group_id = self.get_device_group_id(name=group_name)
        device_id =  self.get_device_id_by_hostname(hostname=device_name)
        return self.update_device_group(group_id=group_id,device_id=device_id,action='add-hosts')

    def remove_device_from_group_by_name(self,group_name,device_name):
        group_id = self.get_device_group_id(name=group_name)
        device_id =  self.get_device_id_by_hostname(hostname=device_name)
        return self.update_device_group(group_id=group_id,device_id=device_id,action='remove-hosts')

    def get_host_group_members_by_id(self,group_id,filter=None,offset=None,limit=5000,sort=None):
        group_members = list()
        query_params = {
            "id":group_id,
            "filter":filter,
            "sort":sort,
            "limit":limit,
            "offset":offset
        }
        params = {k:v for k,v in query_params.items() if v is not None}
        host_group_member_url = f'{self.api_base}/devices/combined/host-group-members/v1'
        members = self.session.get(url=host_group_member_url,params=params)
        self.check_response(members)
        group_members.extend(members.json()['resources'])
        # when the offset is equal to the total, all records have been enumerated
        next_offset = members.json()['meta']['pagination']['offset']
        if members.json()['meta']['pagination']['total'] > next_offset:
            group_members.extend(self.get_host_group_members_by_id(group_id=group_id,filter=filter,offset=next_offset,limit=limit,sort=sort))
        return group_members

    def get_host_group_members_by_name(self,group_name,filter=None,offset=None,limit=None,sort=None):
        group_id = self.get_device_group_id(group_name)
        return self.get_host_group_members_by_id(group_id=group_id,filter=filter,offset=offset,limit=limit,sort=sort)

    def update_group_hosts_by_id(self,src_group_id,dst_group_id,action):
        members = self.get_host_group_members_by_id(src_group_id)
        for member in members:
            resp = self.update_device_group(group_id=dst_group_id,device_id=member['device_id'],action=action)
            self.check_response(resp)
    
    def add_group_hosts_by_id(self,from_group_id,to_group_id):
        return self.update_group_hosts_by_id(src_group_id=from_group_id,dst_group_id=to_group_id,action="add-hosts")

    def add_group_hosts_by_name(self,from_group_name,to_group_name):
        from_group_id = self.get_device_group_id(from_group_name)
        to_group_id = self.get_device_group_id(to_group_name)
        return self.add_group_hosts_by_id(from_group_id=from_group_id,to_group_id=to_group_id)

    def remove_group_hosts_by_id(self,src_group_id,from_group_id):
        return self.update_group_hosts_by_id(src_group_id=src_group_id,dst_group_id=from_group_id,action="remove-hosts")

    def remove_group_hosts_by_name(self,src_group_name,from_group_name):
        src_group_id = self.get_device_group_id(src_group_name)
        from_group_id = self.get_device_group_id(from_group_name)
        return self.remove_group_hosts_by_id(src_group_id=src_group_id,from_group_id=from_group_id)

    def get_num_affected_devices(self,type,ioc_value):
        if type not in ['sha256','sha1','md5','domain']:
            raise ValueError("'type' param must be one of the following values: sha256, sha1, md5, domain")
        ioc_agg_api = f'{self.api_base}/indicators/aggregates/devices-count/v1'
        params = {
            'type':type,
            'value':ioc_value
        }
        count = self.session.get(ioc_agg_api, params=params) 
        self.check_response(count)
        return count.json()['resources']

    #enterprise search function
    def get_affected_devices(self,type,ioc_value,limit=100,offset=None):
        ioc_search_api = f'{self.api_base}/indicators/queries/devices/v1'
        if type not in ['sha256','sha1','md5','domain']:
            raise ValueError("'type' param must be one of the following values: sha256, sha1, md5, domain")
        params = {
            'type':type,
            'value':ioc_value,
            'limit':limit,
            'offset':offset
        }
        devices = self.session.get(ioc_search_api, params=params)
        self.check_response(devices)
        return devices.json()['resources']

    #real-time-response functions
    def new_rtr_session_by_id(self,device_id,origin,queued=False):
        rtr_session_api = f'{self.api_base}/real-time-response/entities/sessions/v1'
        body = {
            "device_id":device_id,
            "origin":origin,
            "queue_offline":queued
        }
        rtr_session = self.session.post(url=rtr_session_api,json=body)
        self.check_response(rtr_session)
        return rtr_session.json()['resources'][0]

    def new_batch_rtr_session_by_id(self,device_ids,existing_batch_id="",queued=False):
        # limitation put in place by CS
        UPPER_BOUND = 10000
        rtr_batch_session_api = f'{self.api_base}/real-time-response/combined/batch-init-session/v1'
        if not isinstance(device_ids,list):
            device_ids = [device_ids]
        if len(device_ids) > UPPER_BOUND:
            iterations = (len(device_ids)//UPPER_BOUND)+1
            batch_ids = []
            start = 0
            end = UPPER_BOUND
            while iterations != 0:
                batch_ids += self.new_batch_rtr_session_by_id(device_ids[start:end],existing_batch_id,queued)
                start = end
                end = end + UPPER_BOUND
                iterations = iterations - 1
            return batch_ids
        else:
            body = {
                "host_ids":device_ids,
                "queue_offline":queued
            }
            if None != existing_batch_id and len(existing_batch_id) > 1:
                body['existing_batch_id'] = existing_batch_id
            rtr_session = self.session.post(url=rtr_batch_session_api,json=body)
            self.check_response(rtr_session)
            batch_id = [rtr_session.json()['batch_id']]
            return batch_id

    def new_rtr_session_by_hostname(self,hostname,origin,queued=False):
        device_id = self.get_device_id_by_hostname(hostname)[0]
        rtr_session = self.new_rtr_session_by_id(device_id,origin,queued)
        return rtr_session

    def run_batch_active_responder_command_by_batch_id(self,batch_id,base_command,command_string,timeout_duration="30s",admin=False):
        timeout_regex = r"^\d{1,2}(([num]?s)|m)$"
        if not re.match(timeout_regex,timeout_duration):
            raise ValueError("timeout_duration must be less than 10m and must be 1-2 digits with ns, us, ms, s, or m unit identifier")
        commands = [
            'cat','cd','clear','cp','encrypt','env','eventlog','filehash','get','getsid','help','history',
            'ipconfig','kill','ls','map','memdump','mkdir','mount','mv','netstat','ps','reg query','reg set',
            'reg delete','reg load','reg unload','restart','rm','runscript','shutdown','unmap','update history',
            'update install','update list','update query','xmemdump','zip']
        if admin:
            active_responder_batch_api = "{0}/real-time-response/combined/batch-admin-command/v1?timeout_duration={1}".format(self.api_base,timeout_duration)
            commands.extend(["put","update history","update install","update list","update query"])
        else:
            active_responder_batch_api = "{0}/real-time-response/combined/batch-active-responder-command/v1?timeout_duration={1}".format(self.api_base,timeout_duration)
        
        cmd_string = command_string.replace("\\","/")
        
        if base_command not in commands:
            raise ValueError(f'{base_command} is not an acceptable value for base_command. Ensure active responder is enabled for this host')
        body = {
            "base_command":base_command,
            "command_string":f'{base_command} {cmd_string}',
            "batch_id":batch_id
        }
        command = self.session.post(url=active_responder_batch_api,json=body)
        self.check_response(command)
        return command

    def run_batch_active_responder_command_by_device_ids(self,device_ids,base_command,command_string,queued=False,timeout_duration="30s",admin=False):
        timeout_regex = r"^\d{1,2}(([num]?s)|m)$"
        if not re.match(timeout_regex,timeout_duration):
            raise ValueError("timeout_duration must be less than 10m and must be 1-2 digits with ns, us, ms, s, or m unit identifier")
        batch_ids = self.new_batch_rtr_session_by_id(device_ids,queued=queued)
        command = {}
        for batch_id in batch_ids:
            resp = self.run_batch_active_responder_command_by_batch_id(batch_id,base_command,command_string,timeout_duration,admin=admin)
            command.update(resp.json()['combined']['resources'])
        return command

    #pass a properly escaped command_string (or raw string r'')
    def run_active_responder_command_by_session_id(self,session_id,base_command,command_string,admin=False):
        commands = [
            'cat','cd','clear','cp','encrypt','env','eventlog','filehash','get','getsid','help',
            'history','ipconfig','kill','ls','map','memdump','mkdir','mount','mv','netstat','ps',
            'reg query','reg set','reg delete','reg load','reg unload','restart','rm','runscript',
            'shutdown','unmap','xmemdump','zip']
        if admin:
            active_responder_api = f'{self.api_base}/real-time-response/entities/admin-command/v1'
            commands.extend(["put","update history","update install","update list","update query"])
        else:
            active_responder_api = f'{self.api_base}/real-time-response/entities/active-responder-command/v1'
        cmd_string = command_string.replace("\\","/")
        if base_command not in commands:
            raise ValueError(f'{base_command} is not an acceptable value for base_command. Ensure active responder is enabled for this host')
        body = {
            "base_command":base_command,
            "command_string":f'{base_command} {cmd_string}',
            "session_id":session_id 
        }
        command = self.session.post(url=active_responder_api,json=body)
        self.check_response(command)
        return command

    def run_active_responder_command_by_device_id(self,device_id,origin,base_command,command_string,queued=False,admin=False):
        rtr_session = self.new_rtr_session_by_id(device_id,origin,queued)
        command = self.run_active_responder_command_by_session_id(rtr_session['session_id'],base_command,command_string,admin)
        return command

    def run_active_responder_command_by_hostname(self,hostname,origin,base_command,command_string,queued=False,admin=False):
        rtr_session = self.new_rtr_session_by_hostname(hostname,origin,queued)
        command = self.run_active_responder_command_by_session_id(rtr_session['session_id'],base_command,command_string,admin)
        return command
    
    def get_active_responder_command_result(self,cloud_request_id,sequence_id=0):
        params = {'cloud_request_id':cloud_request_id,'sequence_id':sequence_id}
        result = self.session.get('{0}/real-time-response/entities/active-responder-command/v1'.format(self.api_base),params=params)
        self.check_response(result)
        return result.json()['resources'][0]['stdout']

    def get_file_by_hostname(self,hostname,filepath,origin,queued=False):
        command = self.run_active_responder_command_by_hostname(hostname,origin,"get",filepath,queued)
        return command

    def get_file_by_device_id(self,device_id,filepath,origin,queued=False):
        command = self.run_active_responder_command_by_device_id(device_id,origin,"get",filepath,queued)
        return command

    def logoff_user_by_hostname(self,hostname,username,origin,queued=False):
        command = self.run_active_responder_command_by_hostname(hostname,origin,"runscript",f'-CloudFile=\"Logout-User\" -CommandLine=\"{username}\"',queued)
        return command

    def get_browser_history_files_by_hostname(self,hostname,origin,queued=False):
        #have to pull it out b/c requires two commands
        #the sleeps are stupid but the commands need to be sequential and were happening too quickly otherwise
        rtr_session = self.new_rtr_session_by_hostname(hostname,origin,queued)
        command = self.run_active_responder_command_by_session_id(rtr_session['session_id'],"runscript",f'-CloudFile=\"Get-BrowserHistoryFiles\" -CommandLine=\"\"')
        sleep(1)
        if command.json()['errors'] == None and command.ok:
            command = self.run_active_responder_command_by_session_id(rtr_session['session_id'],"get",r"C:\Temp\BrowserHistory.zip")
            sleep(1)
            _ = self.run_active_responder_command_by_session_id(rtr_session['session_id'],"rm",r"C:\Temp\BrowserHistory.zip")
        return command

    def enable_psremoting_by_hostname(self,hostname,origin,queued=False):
        command = self.run_active_responder_command_by_hostname(hostname=hostname,origin=origin,base_command="runscript",command_string=f'-CloudFile=\"Enable-PSRemoting\" -CommandLine=\"\"',queued=queued)
        return command
    
    def disable_psremoting_by_hostname(self,hostname,origin,queued=False):
        command = self.run_active_responder_command_by_hostname(hostname=hostname,origin=origin,base_command="runscript",command_string=f'-CloudFile=\"Disable-PSRemoting\" -CommandLine=\"\"',queued=queued)
        return command

    def inject_lsa_secret_by_hostname(self,hostname,origin,queued=False):
        command = self.run_active_responder_command_by_hostname(hostname=hostname,origin=origin,base_command="runscript",command_string=f'-CloudFile=\"Inject-LSASecret\" -CommandLine=\"\"',queued=queued)
        return command

    def get_chrome_extensions_by_hostname(self,hostname,origin,queued=False):
        #have to pull it out b/c requires two commands
        #the sleeps are stupid but the commands need to be sequential and were happening too quickly otherwise
        rtr_session = self.new_rtr_session_by_hostname(hostname,origin,queued)
        command = self.run_active_responder_command_by_session_id(rtr_session['session_id'],"runscript",f'-CloudFile=\"Get-ChromeExtensions\" -CommandLine=\"\"')
        sleep(1)
        if command.json()['errors'] == None and command.ok:
            command = self.run_active_responder_command_by_session_id(rtr_session['session_id'],"get",r"C:\Temp\ChromeExtensions.zip")
            sleep(1)
            _ = self.run_active_responder_command_by_session_id(rtr_session['session_id'],"rm",r"C:\Temp\ChromeExtensions.zip")
        return command

    def get_sensor_version(self,filter,limit=1,sort="release_date|desc"):
        params = {
            "filter":filter,
            "limit":limit,
            "sort":sort
        }
        sensor = self.session.get("{0}/sensors/combined/installers/v1".format(self.api_base),params=params)
        self.check_response(sensor)
        return sensor.json()['resources']

    def get_latest_sensor_version(self,filter):
        sensor = self.get_sensor_version(filter)
        return sensor[0]

    def get_sensor(self,sha256):
        params = {
            "id":sha256
        }
        sensor = self.session.get("{0}/sensors/entities/download-installer/v1".format(self.api_base),params=params)
        self.check_response(sensor)
        return sensor

    def download_sensor(self,sha256,filepath):
        sensor = self.get_sensor(sha256)
        with open(filepath,"wb") as file:
            file.write(sensor.content)
        return True

    def download_latest_sensor(self,filter,filepath):
        sha256 = self.get_latest_sensor_version(filter)['sha256']
        return self.download_sensor(sha256,filepath)


    def download_latest_ubuntu_sensor(self,filepath):
        filter = "os:'Ubuntu'+os_version:!'*arm64'"
        return self.download_latest_sensor(filter,filepath)

    ###
    # new dev
    def vuln_search(self,vuln_filter):
        spotlight_api = f'{self.api_base}/spotlight/queries/vulnerabilities/v1'
        vuln = self.session.get(spotlight_api, params={"filter":vuln_filter})
        return vuln

    def get_vulnerable_hosts(self,cve):
        vuln_query = f'cve.id={cve}'
        vuln = self.vuln_search(vuln_query)
        return vuln



    ##########################
    #really rough stubbing below
    def get_processes_id(self,type,ioc_value,limit=100,offset=None,**host):
        process_ioc_api = f'{self.api_base}/indicators/queries/processes/v1'
        if type not in ['sha256','sha1','md5','domain']:
            raise ValueError("'type' param must be one of the following values: sha256, sha1, md5, domain")
        if 'id' in host:
            device_id = host['device_id']
        elif 'hostname' in host:
            device_id = self.get_device_id_by_hostname(host['hostname'])
        else:
            raise IndexError("'host' param must contain either a 'hostname' key with the system name or 'id' key with the device id")  
        params = {
            'device_id':device_id,
            'type':type,
            'value':ioc_value,
            'limit':limit,
            'offset':offset
        }
        return self.session.get(process_ioc_api, params=params)

    def get_process_detail(self,id):
        process_api = f'{self.api_base}/processes/entities/processes/v1'
        params={'ids':id}
        return self.session.get(process_api,params=params)