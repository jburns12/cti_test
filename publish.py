"""Convert ATT&CK data to STIX format"""
import argparse
import os
import urllib3
import errno
import uuid
import shutil

import simplejson as json

from modules import collections, cti, download, lookup, scrub, util

# suppress InsecureRequestWarning: Unverified HTTPS request is being made
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def gen_marking_definition(output_dir, source):
    try:
        os.makedirs(output_dir + source + '/marking-definition')
        with open(output_dir + source + '/marking-definition/marking-definition-fa42a846-8d90-4e51-bc29-71d5b4802168.json', 'w') as f:
           stix = {}
           stix['type'] = 'bundle'
           stix['id'] = 'marking-definition-fa42a846-8d90-4e51-bc29-71d5b4802168'
           stix['spec_version'] = '2.0'
           stix['objects'] = []
           stix_object = {}
           stix_object['type'] = 'marking-definition'
           stix_object['id'] = 'marking-definition-fa42a846-8d90-4e51-bc29-71d5b4802168'
           stix_object['created_by_ref'] = 'identity--c78cb6e5-0c4b-8297-d1b8b55e40b5'
           stix_object['created'] = '2017-06-01T00:00:00Z'
           stix_object['definition_type'] = 'statement'
           stix_object['definition'] = {}
           stix_object['definition']['statement'] = 'Copyright 2017, The MITRE Corporation'
           stix['objects'].append(stix_object)
           f.write(json.dumps(stix, indent=4))
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    return stix_object

def main():
    parser = argparse.ArgumentParser(description='Convert ATT&CK data to STIX')
    parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')
    parser.add_argument('-o', '--output', action='store', help='output directory')
    parser.add_argument('-t', '--token', action='store', help='GitHub token')
    parser.add_argument('-u', '--user', action='store', help='Github user')
    parser.add_argument('-e', '--email', action='store', help='Github email')

    args = parser.parse_args()
    
    stix_to_attack_lookup = lookup.create_stix_to_attack_dict()
    attack_to_name_lookup = lookup.create_attack_to_name_dict()
    domain_to_uuid_lookup = lookup.create_domain_to_uuid_dict()
    uuid_to_domain_lookup = lookup.create_uuid_to_domain_dict()

    # Preserve the order of the first two elements of this list to ensure output accuracy
    endpoints = ['attack-patterns', 'relationships', 'course-of-actions', 'identities', 'intrusion-sets', 'malwares', 'tools']
    valid_domains = list(domain_to_uuid_lookup.keys())

    if args.output:
        if args.output[-1] != '/':
            args.output = args.output + '/'
        output_dir = args.output
    else:
        output_dir = 'output/'

    if args.token and args.user and args.email:
        try:
            shutil.rmtree(output_dir)
        except Exception as ex:
            pass
        
        if cti.clone_repo(output_dir) is False:
            return

    for domain in valid_domains:
        try:
            shutil.rmtree(output_dir + domain)
        except Exception as ex:
            pass
        try:
            os.makedirs(output_dir + domain)
        except OSError as ex:
            if ex.errno != errno.EEXIST:
                raise

    if args.verbose:
        print('{0} Output directory: {1}'.format(util.timestamp(), output_dir))

    # Create a dictionary of ATT&CK source dictionaries
    domain_json = {}
    domain_ids = {}
    div_output = {}

    for domain in valid_domains:
        domain_json[domain] = {}
        domain_json[domain]['type'] = 'bundle'
        domain_json[domain]['id'] = 'bundle--{0}'.format(uuid.uuid4())
        domain_json[domain]['spec_version'] = '2.0'
        domain_json[domain]['objects'] = []

    for domain in valid_domains:
        domain_ids[domain] = []

    for endpoint in endpoints:
        div_output[endpoint] = download.stix(endpoint=endpoint)

    domain_ids = collections.set_collections(div_output, domain_ids, uuid_to_domain_lookup)
    for key in domain_ids:
        domain_ids[key] = list(set(domain_ids[key]))
    for endpoint in endpoints:
        if args.verbose:
            print('{0} Pulling data from /{1} endpoint'.format(util.timestamp(), endpoint))
        output = download.stix(endpoint=endpoint)

        if endpoint != 'identities':
            if args.verbose:
                print('{0} Scrubbing and transforming data'.format(util.timestamp()))
            output = scrub.append_custom_fields(json_blob=output)
            output = scrub.remove_empty_fields(output)
            output = scrub.filter_by_id(json_blob=output, lookup=stix_to_attack_lookup)
            output = scrub.transform_text(json_blob=output, attack_to_name_lookup=attack_to_name_lookup)
        else:
            if args.verbose:
                print('{0} Scrubbing and transforming data'.format(util.timestamp()))
            output = scrub.filter_identity(json_blob=output)

        for domain in valid_domains:
            try:
                if endpoint != 'identities':
                    output_path = output_dir + domain + '/' + endpoint[:-1]
                    os.makedirs(output_path)
                elif endpoint == 'identities':
                    output_path = output_dir + domain + '/identity'
                    os.makedirs(output_path)
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise 

        if args.verbose:
            print('{0} Exporting JSON'.format(util.timestamp()))

        for obj in output:
            stix = {}
            stix['type'] = 'bundle'
            stix['id'] = 'bundle--{0}'.format(uuid.uuid4())
            stix['spec_version'] = '2.0'
            stix['objects'] = []
            attributes = ['type', 'id', 'created_by_ref', 'created', 'modified', 'name', 'description', 'aliases', 'labels', 'kill_chain_phases', 'external_references', 'identity_class', 'object_marking_refs', 'x_mitre_detection', 'x_mitre_detection', 'x_mitre_platforms', 'x_mitre_data_sources', 'x_mitre_effective_permissions', 'x_mitre_defense_bypassed', 'x_mitre_permissions_required', 'x_mitre_system_requirements', 'x_mitre_remote_support','x_mitre_network_requirements', 'x_mitre_contributors','x_mitre_aliases', 'source_ref', 'target_ref']
            stix_object = {}
                
            for attribute in attributes:
                try:
                    if (obj['attributes'][attribute]):
                        stix_object[attribute] = obj['attributes'][attribute]
                except KeyError as ex:
                    pass 
            stix['objects'].append(stix_object)

            for domain in valid_domains:
                if obj['attributes']['id'] in domain_ids[domain]:
                    domain_json[domain]['objects'].append(stix_object)
                    with open(output_dir + '/' + domain + '/' + obj['type'] + '/' + obj['attributes']['id'] + '.json', 'w') as f:
                        f.write(json.dumps(stix, indent=4))
                
    for domain in valid_domains:
        if domain_json[domain]['objects']:
            if args.verbose:
                print('{0} Writing {1}.json to root output directory'.format(util.timestamp(), domain))
            marking_def = gen_marking_definition(output_dir, domain)
            domain_json[domain]['objects'].append(marking_def)
            with open(output_dir + '/' + domain + '/' + domain + '.json', 'w') as f:
                f.write(json.dumps(domain_json[domain], indent=4))
            for endpoint in endpoints:
                if endpoint == 'identities':
                    endpoint = 'identitys'
                if not os.listdir(output_dir + '/' + domain + '/' + endpoint[:-1]):
                    os.rmdir(output_dir + domain + '/' + endpoint[:-1])
        else:
            shutil.rmtree(output_dir + '/' + domain)

if __name__ == "__main__":
    main()